## HTB Dab (Hard) - Writeup

Difficulty: Hard

Initial foothold was gained by fuzzing cookie names and values, leading to the discovery of a hidden authentication mechanism and access to restricted functionality.
An exposed Memcached instance was exploited to extract sensitive data, including valid credentials.
Privilege escalation was achieved via shared library hijacking in a misconfigured SUID binary, allowing execution of arbitrary code with root privileges.

---

## Nmap 

#### The nmap scan revealed four open ports:  

![obraz](https://github.com/user-attachments/assets/c4950260-c4fd-41c4-afb0-e91f06fd36e9)


## Port 21 - FTP

I'll start with ftp as I often do when it's open on CTF's.   
We can login with username "anonymous" and a blank password "".  

![obraz](https://github.com/user-attachments/assets/f83e2c35-5262-4c7f-9da8-79d3435bac24)

There is only one file and it is a .jpg photo.  
I'll transfer it with GET command.  

![obraz](https://github.com/user-attachments/assets/e7ccdb0d-e783-4f67-ae5e-ab58e138c430)

First I will check metadata with exiftool.  

![obraz](https://github.com/user-attachments/assets/6c1b7327-d90e-4108-b35d-7afc97dfe946)

Nothing intresting there.  

Steganography is a way to hide secret information or even entire files inside normal files, like images or audio.  
For example, a document can be hidden inside a photo without visibly altering the image.    
We will now look for hidden files.  

![obraz](https://github.com/user-attachments/assets/55d6818b-6635-4836-bbed-7f1b4101d692)  

There is a hidden file but it's just a rabbit hole.  


## Port 80 - Website 

![obraz](https://github.com/user-attachments/assets/16c059f8-bb7e-4fa5-ad3a-5894894f98f3)

Website contains login page, default credentials didin't work.  
We can try a bruteforce attack, normally we would bruteforce usernames first but I'll just guess that there is an admin account:  

![obraz](https://github.com/user-attachments/assets/f6756c03-7f21-4201-a661-787190d0bce1)

We got valid credentials.  
Let's use them to login to the website.  

![obraz](https://github.com/user-attachments/assets/b71def5c-cc04-437d-9217-2e4aefd926a8)

It doesn't contain anything intresting, we will now move to port 8080 and maybe comeback to port 80 later.  



## Port 8080 - Second Website 

![obraz](https://github.com/user-attachments/assets/0758865b-4bd6-46f0-b67a-0e77f355dfe7)

It gives us "Access Denied" but also a hint that there is a cookie that could give us more access.  
We will perform Fuzzing on the Cookie name:  

![obraz](https://github.com/user-attachments/assets/142ee62c-1185-474f-83e6-c73cfc438a4f)

After running it for the first time we noticed that everything returns 30 W, meaning we need to us --hw 30 to filter it out as shown above.  



















