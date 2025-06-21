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
