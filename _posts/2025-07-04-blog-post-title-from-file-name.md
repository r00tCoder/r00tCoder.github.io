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





















































