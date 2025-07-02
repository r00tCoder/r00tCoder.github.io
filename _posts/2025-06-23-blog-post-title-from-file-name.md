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
```
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
```
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
```
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





























