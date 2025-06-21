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

























































