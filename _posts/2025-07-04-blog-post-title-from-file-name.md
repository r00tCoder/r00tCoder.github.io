## HTB Tenet (Medium) - Writeup

Difficulty: Medium

On the Tenet machine, I discovered a WordPress site and found a developer comment referencing sator.php and a backup file.  
Accessing sator.php.bak revealed a PHP deserialization vulnerability, which I exploited to upload a webshell.  
I then found database credentials in wp-config.php, used them to switch to user neil.  
Finally escalated to root by abusing a race condition in a misconfigured enableSSH.sh script.  

---

## Nmap 

#### The nmap scan revealed two open ports:


