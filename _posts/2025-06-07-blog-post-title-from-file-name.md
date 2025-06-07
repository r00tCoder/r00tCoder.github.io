
## HTB Falafel - Writeup

Difficulty: Hard

Initial access combined SQL injection with PHP type juggling to bypass login, gaining admin web access.  
A filename length trick bypassed upload restrictions, enabling remote code execution with a PHP reverse shell.  
Privilege escalation involved extracting framebuffer data via video group access to find credentials, then using disk group permissions with debugfs for further escalation.  

---

## Nmap 

#### The nmap scan revealed two open ports:  

![obraz](https://github.com/user-attachments/assets/6a220eb0-32fb-4c58-8d9f-8083c92db1a3)  

## Port 80 - Website 

![obraz](https://github.com/user-attachments/assets/cc28b3db-36e5-430d-b2e6-36692437d945)  

First I'll add falafel.htb to /etc/hosts.  
Next, I checked the robots.txt file, but it was empty.  
There is a login page:

![obraz](https://github.com/user-attachments/assets/93a11112-192e-4ff5-bb5f-08f34c3ccc32)


I tried some basic sql injection and default credentials but it didn't work.  
Now we can look for exposed directories using Feroxbuster.  
I'll use a list from Seclists first:  

![obraz](https://github.com/user-attachments/assets/a5fcc7c1-d122-4e7f-85cf-d1f91871968f)  

We've successfully found two files:  
**cyberlaw.txt** and **Connection.php**  
Let's take a look at cyberlaw.txt:  

![obraz](https://github.com/user-attachments/assets/dd6749c1-254c-4514-8c70-a630d0578019)

It contains new user "chris" and a hint that we will be able to login without a password.  

## Login Page  

Now we will move to the login page and try to bypass authentication somehow.  
My first idea was to run sqlmap against it.  
For it to work we will open Burpsuite turn intercept on and catch login request.  

![obraz](https://github.com/user-attachments/assets/21bd2ea4-5493-49cb-8e1b-d1fde5c86063)  

Copy the request to a file and save it.  

![obraz](https://github.com/user-attachments/assets/8644f8a1-6a60-4cea-841d-bd449a9910b8)

Now we can run sqlmap.  
```
sqlmap -r chris.req
```

Unfortunately it didn't work.  
![obraz](https://github.com/user-attachments/assets/8033077d-5e31-4b1b-adc1-e74aa0214265)  

Observing the login page’s behavior, we notice it responds with “Try again” when the username doesn’t exist, but returns “Wrong identification: admin” when the username is valid.  
Meaning we can try blind sql injection. In order to do that we can use --string parameter.  

```
sqlmap -r chris.req --string "Wrong identification"
```
![obraz](https://github.com/user-attachments/assets/22c3c9a7-f6e3-4ebe-bab3-0b0321ffcdb5)  

Now all we need to do is add --dump parameter and wait.  
```
sqlmap -r chris.req --string "Wrong identification" --dump
```

![obraz](https://github.com/user-attachments/assets/81c8baa8-be1d-4a5b-ab4d-aadf22605c14)

Copy those two passwords into a file and save.  
Then proceed with hashcat module 0 - which is md5.  

![obraz](https://github.com/user-attachments/assets/7a38a03a-7544-4f5a-b6a5-0d3cd42be273)

After waiting for some time we get a result.  

![obraz](https://github.com/user-attachments/assets/30bd5359-95a4-45ac-8eef-ef545e958354)

## Elevate from chris to admin

We can log in using the credentials chris:juggling.  
Chris’s profile description heavily hints at a PHP type juggling vulnerability.  
The admin’s password hash starts with 0e, which PHP interprets as scientific notation for zero when using loose comparison (==).  

In the code, authentication likely uses a loose comparison like:  
```
if ($password_hash == $stored_hash) { ... }
```
Because the hash starts with 0e, PHP treats it as 0. If we supply a password that when hashed also evaluates to 0 under loose comparison the comparison becomes:  
```
0 == 0
``` 
which evaluates to true, allowing us to bypass authentication and gain admin access.   
We can use this post as a resource:  
```
https://web.archive.org/web/20220118182443/https://www.whitehatsec.com/blog/magic-hashes/
```

There is a magic number that when hashed will start with 0e.  
We can verify that:  

![obraz](https://github.com/user-attachments/assets/2aec1ea4-d035-4c1d-9d08-3749b70de908)

Now if we use this as a password it will evaluate to 0, leading to authentication bypass.  

## File Upload to shell access

Let's login with  admin:240610708  
We have ability to upload an image from the URL that we can specify.  
First test a normal .png file:  

![obraz](https://github.com/user-attachments/assets/53f84436-5d4e-493a-a3a2-c26bb1ede0b9)

Output:  

![obraz](https://github.com/user-attachments/assets/3a2a4424-aa28-4b49-94b4-154aa56b7e36)

It discloses two important information:  
1. File upload location  
2. We're using wget to upload a file  

Let's check if we can reach this file:  

![obraz](https://github.com/user-attachments/assets/d1181cc4-d925-4a7f-8463-9517b597cb71)

We can reach this file, meaning now we have to bypass filter to upload php file containing a reverse shell.  
First thing I tried was uploading test.php%00.png, but it gave an error.  
We can try other methods to bypass filters but they didn't work.  
The admin's profile description hints at "Limits," specifically referring to wget's filename character length limit.  

![obraz](https://github.com/user-attachments/assets/56180dd7-ff4d-4c59-8459-fcca84f6516b)

Linux character limit for a filename is 255, but wget will shorten filename to 236 characters which can be abused to bypass extension filter.  
Let's first check it by uploading a file with 255 character long filename:  

![obraz](https://github.com/user-attachments/assets/7313eb8e-508d-450d-ad22-c6d18c5f4c95)

251 characters of A's and 4 characters for .png, resulting in 255 characters total.  
Now upload it with python server to the site.  

![obraz](https://github.com/user-attachments/assets/90a47040-5829-4e11-9255-576763dd553f)

We can copy the truncated filename and use the wc -c command to count its length in characters.  

![obraz](https://github.com/user-attachments/assets/ed555fa9-cb7e-4bff-9679-ff3b4a7ed7bc)

How to exploit it?  
Wget truncates filenames longer than 236 characters. By naming a file with 232 "A" characters + .php.png (240 chars total), the last 4 .png get cut off, leaving .php and bypassing upload filters.  

![obraz](https://github.com/user-attachments/assets/8f9651b1-98cd-4366-83ba-31e5f3f2fcbc)

Contents of this file in our case will be pentest monkey reverse shell.  
```
https://github.com/pentestmonkey/php-reverse-shell
```

After we upload our reverse shell we will be able to curl it (notice that we specify previously discovered file location):  

![obraz](https://github.com/user-attachments/assets/f7d77d18-cd48-46f4-ba1c-7e5d242d559c)

Resulting in a shell access:  

![obraz](https://github.com/user-attachments/assets/e5fbaf72-7c1a-49aa-a0b6-eff3eeede516)





























