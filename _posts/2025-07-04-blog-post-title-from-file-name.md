## HTB Tenet (Medium) - Writeup

Difficulty: Medium

On the Tenet machine, I discovered a WordPress site and found a developer comment referencing sator.php and a backup file.  
Accessing sator.php.bak revealed a PHP deserialization vulnerability, which I exploited to upload a webshell.  
I then found database credentials in wp-config.php, used them to switch to user neil.  
Finally escalated to root by abusing a race condition in a misconfigured enableSSH.sh script.  

---

## Nmap 

#### The nmap scan revealed two open ports:

<img width="944" height="489" alt="obraz" src="https://github.com/user-attachments/assets/b026723f-f60b-4dbe-ae80-b06ab07c9a34" />


## Port 80 - Website

On port 80 we have default apache page.  

<img width="1281" height="765" alt="obraz" src="https://github.com/user-attachments/assets/fa982757-a908-4bba-94ef-2e1f90300274" />

Now we will do directory busting with feroxbuster:  
```
feroxbuster --url http://10.10.10.223
```

<img width="947" height="516" alt="obraz" src="https://github.com/user-attachments/assets/b2831233-0e87-476b-b2a9-e45341129a9c" />

We've found wordpress directories.  
Everytime I encounter a website made in wordpress I run wpscan to look for vulnerable plugins.  
```
wpscan --url http://10.10.10.223 --plugins-detection mixed --api-token xxxxxxx
```

<img width="951" height="414" alt="obraz" src="https://github.com/user-attachments/assets/61d3140b-6f4d-4c32-a4c4-96f0b25fa58b" />

If you don't have an api token just create an account on wpscan website and claim yours.  
We used the mixed detection method, which performs plugin brute-forcing.  
If we had relied solely on passive detection, many plugins would have been missed.  

<img width="954" height="356" alt="obraz" src="https://github.com/user-attachments/assets/93001081-e523-4421-a43f-4e9d65e3d087" />

It has found akismet but besides that nothing of interest.  
Now I'll add tenet.htb to /etc/hosts  

<img width="1273" height="762" alt="obraz" src="https://github.com/user-attachments/assets/2c4665bc-a354-47b8-82ec-20a96a7c2c32" />

While exploring the site, I came across a comment:  

<img width="1269" height="757" alt="obraz" src="https://github.com/user-attachments/assets/ff0e22af-9ec5-413f-8ce1-93457c24c061" />

Let's look for this "sator" file.  
On tenet.htb it didn't work:  
```
http://tenet.htb/sator.php
```

But on apache default page it worked:  
```
http://10.10.10.223/sator.php
```

<img width="1273" height="386" alt="obraz" src="https://github.com/user-attachments/assets/0eb5c304-ee2a-4919-84dd-b6dd00d77250" />

They also mentioned sator backup file, let's try to retrieve it:  
```
http://10.10.10.223/sator.php.bak
```

We can download it and look at the source code:  

<img width="941" height="484" alt="obraz" src="https://github.com/user-attachments/assets/d05c332c-a01c-4226-adaf-ded2c34edcc7" />

```php
<?php

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
```

First thing that immediately stands out is dangerous usage of unserialize function.  
This script passes user input to unserialize() which can be abused in deserialization attack.  

The script takes user input from the arepo GET parameter and passes it directly to the unserialize() function.  
This allows us to create a PHP object from user input.  
When the script finishes, PHP automatically destroys all objects, which triggers the __destruct() method of our crafted object.  
It means that __desctruct() will run against our object.  










































