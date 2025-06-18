## HTB Falafel (Hard) - Writeup

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
