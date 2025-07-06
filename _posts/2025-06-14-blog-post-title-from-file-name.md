## HTB Sandworm (Medium) - Writeup  

Difficulty: Medium  

This box revolves around a Flask web app with GPG-based functionality.  
By injecting SSTI payloads via GPG key names and signature verification, we achieve RCE.  
Enumeration reveals credentials and a Rust binary (tipnet) run via cron as root, which imports a custom logger crate we can write to—allowing for privilege escalation.  
Finally, we exploit a known Firejail vulnerability (CVE-2022-31214) to escalate to root.  

---

## Nmap 

#### The nmap scan revealed three open ports:  

![obraz](https://github.com/user-attachments/assets/f64289ac-22cf-4e03-8e80-8c45e9321d41)  


## Port 80 - Website  

This website just redirects to httpsL//ssa.htb  
We'll add it to /etc/hosts and move to 443  



## Port 443 - https website  

![obraz](https://github.com/user-attachments/assets/46fd1c0b-d1ad-4212-b0b6-24db7e905246)  

After quick enumeration I found that this app is written in flask.  
The site exposes three main routes:  

+  /contact
+  /pgp
+  /guide

/pgp contains pgp key, first thing that came to my mind is to import it to kali.  
It can be done by putting it in a file and using:  
```
gpg --import key
```
![obraz](https://github.com/user-attachments/assets/557ef4a9-d850-46b5-8f67-f8acbc623bde)

Now we will be able to encrypt messages with this key.  
On the contact page we can send encrypted messages:  

![obraz](https://github.com/user-attachments/assets/3cde4962-4abd-4770-a569-153e8727bfc4)

On the guide page there are three functionalities:  
+  Decrypting
+  Encrypting
+  Verifying Signatures

Let's test them one by one starting with Decryption.  
Our goal is to observe how this site works to look for anything that might be abused.  

It can be encrypted with the following command:  
```
gpg --armor --recipient atlas@ssa.htb --encrypt message.txt -o -
```

![obraz](https://github.com/user-attachments/assets/94b3c21b-dbf1-4b70-8d03-5bc6bf9c7c39)

We can now paste this message and click on "Decrypt".  

![obraz](https://github.com/user-attachments/assets/15b62683-bf4e-4ab7-84a9-228936d57492)

It just decrypts but there is nothing unusual.  





































































