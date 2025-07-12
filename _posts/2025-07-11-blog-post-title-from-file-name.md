## HTB Writer (Medium) - Writeup

Difficulty: Medium

Writer was a cool and challenging box that required digging into source code, SQL injection, and chaining a few clever tricks to get root.  
I started with an SQL injection that allowed both authentication bypass and file read, which exposed the application’s source code.  
From there, I exploited a command injection vulnerability in the image upload functionality by chaining local file access with a manipulated filename.  
With a shell as www-data, I extracted Django credentials, cracked a user hash, and pivoted to kyle.  
Privilege escalation to john was achieved by injecting a reverse shell into a Postfix mail filter script and triggering it via SMTP.  
Finally, I abused write access to an APT config file to escalate to root through a cron-executed apt-get hook.  

---

## Nmap 

#### The nmap scan revealed four open ports:  

<img width="935" height="521" alt="obraz" src="https://github.com/user-attachments/assets/0db0f792-0a0c-4113-bb00-0656c1308ca3" />



## Port 445 - SMB

When I encounter SMB or FTP, I usually start my enumeration there by checking for anonymous or guest login.  
For smb it can be done with netexec tool:  
```
nxc smb 10.10.11.101 -u 'a' -p ''
```


<img width="939" height="188" alt="obraz" src="https://github.com/user-attachments/assets/de573a80-0cac-472a-aee0-f8a234c73770" />

It worked let's check shares now:  
```
nxc smb 10.10.11.101 -u 'a' -p '' --shares
```

<img width="950" height="206" alt="obraz" src="https://github.com/user-attachments/assets/087145ef-f172-42e4-bae4-1eb5b085a0b7" />

Unfortunately, no shares were accessible, so I moved on to enumerating the HTTP service.    



## Port 80 - Website  

I'll add writer.htb to /etc/hosts   

<img width="1262" height="772" alt="obraz" src="https://github.com/user-attachments/assets/19e4c07c-18ee-4652-b739-b08e2a925c59" />

on "About" page we found an email:  
+  admin@writer.htb  

There is also contact page but it doesn't work.  
Next, I performed subdomain fuzzing using wfuzz, but it didn’t yield any results:  

<img width="948" height="258" alt="obraz" src="https://github.com/user-attachments/assets/0fa1d7cf-e985-4143-8c5e-e040ea89e28b" />


After that I did directory busting with wfuzz:  

<img width="944" height="144" alt="obraz" src="https://github.com/user-attachments/assets/03453099-c2f4-4970-95b7-a631cba49a9f" />

<img width="944" height="528" alt="obraz" src="https://github.com/user-attachments/assets/620e8f20-40e3-43a7-87ae-275bd703ef6a" />

It has found /administrative directory.  
It contains a login page:  

<img width="1272" height="762" alt="obraz" src="https://github.com/user-attachments/assets/59df1d83-f5b4-4323-b5f3-c57cbea2d33b" />

First I tried brute-forcing with hydra - didn't work:  
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.11.101 http-post-form "/administrative:username=^USER^&password=^PASS^:Incorrect credentials"
```

<img width="942" height="172" alt="obraz" src="https://github.com/user-attachments/assets/59c3cdb7-2004-40b4-b850-676eca5ea461" />

It turned out that  simple sql injection worked for authentication bypass.  
Username field was injectable:  
```
' or 1=1-- -
```

<img width="1274" height="770" alt="obraz" src="https://github.com/user-attachments/assets/5f365bec-d109-4709-b42e-c9ba36b2cf47" />

We get logged in.  
I tried uploading an image with webshell but it didn't work.  


## Exploitation with Sqlmap  

Then I changed approach and came back to sql injection.  
We've ran sqlmap on username parameter.  
First we need to catch login request with burpsuite:  

<img width="1268" height="721" alt="obraz" src="https://github.com/user-attachments/assets/880a2328-3f02-4de3-9ff5-fa04600b8e3b" />

Then we ran sqlmap:  

<img width="945" height="521" alt="obraz" src="https://github.com/user-attachments/assets/195ebf5e-cc80-40ba-974a-789aff8f2eb8" />

<img width="947" height="345" alt="obraz" src="https://github.com/user-attachments/assets/25d3f0ef-b9d9-4d49-9bf2-33368cb40e98" />

From there it's a standard workflow - discover database name, then table names, then dump specific table:  
```
sqlmap -r req.txt --dbs --batch
```
<img width="941" height="142" alt="obraz" src="https://github.com/user-attachments/assets/6b957db9-05cc-4331-9776-82609992b021" />

<img width="947" height="71" alt="obraz" src="https://github.com/user-attachments/assets/0182ea85-2fca-4247-8534-7230c39e4ec3" />

Now we want to find table names in "Writer" database:  
```
sqlmap -r req.txt -D writer --tables --batch
```

<img width="939" height="118" alt="obraz" src="https://github.com/user-attachments/assets/79fd6d8d-43d1-441d-861b-78818c587b34" />

Users table will most likely contain password hash which is a thing of interest ofc.  











































