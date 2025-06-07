
## HTB Falafel - Writeup

Difficulty: Hard

This Active Directory box was especially challenging due to a firewall that blocked many connections, adding an extra layer of difficulty.  
The journey began with decrypting a password from Jenkins, which granted WinRM access as a user.  
From there, abusing ACLs became crucial for escalating privileges.  
Each step deepened my understanding of AD exploitation, making it a rewarding and insightful challenge.  

---

## Nmap 

#### The nmap scan revealed three open ports:
