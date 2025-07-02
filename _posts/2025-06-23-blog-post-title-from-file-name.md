## HTB Epsilon (Medium) - Writeup  
  
Difficulty: Medium  

AWS keys were found exposed in a git repository on the webserver.    
Using those keys, the AWS command line was exploited to access cloud functions and retrieve a secret.   
That secret was then used to exploit the site for code execution with SSTI and gain an initial shell.    
Finally, a backup script was abused to escalate to root and capture the flag.   
---

## Nmap 

#### The nmap scan revealed three open ports:

![obraz](https://github.com/user-attachments/assets/9be0b7ea-b767-4772-b2e2-3ad9771c9b31)


 
