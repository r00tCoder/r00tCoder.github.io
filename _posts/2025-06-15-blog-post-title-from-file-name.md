## HTB Logforge (Medium) - Writeup

Difficulty: Medium

Discovered a Tomcat server with a /manager panel, accessed via a 403 bypass using a path traversal trick.  
Identified and exploited Log4Shell by injecting a JNDI payload in a logged parameter, leading to RCE.  
Gained a reverse shell using a serialized CommonsCollections gadget via JNDI Exploit Kit.  
Escalated to root by exfiltrating environment variables through Log4j to retrieve FTP credentials, then SSH’ed in with a leaked private key.  

---

## Nmap 

#### The nmap scan revealed two open and two filtered ports:  

![obraz](https://github.com/user-attachments/assets/0ece98b9-cef6-4d45-a3a3-f90b4ee531e8)



## Port 80 - Website  

The website consists solely of a static image, with no interactive or visible functionality.  

![obraz](https://github.com/user-attachments/assets/d312d04b-86a8-4f03-8c27-6f5f9e1c7776)  

Running Feroxbuster revealed the /admin directory, which returns a 403 Forbidden error.  

![obraz](https://github.com/user-attachments/assets/5a2e7c4a-5b0f-4ec1-aaca-9911d45f078e)

It also revealed that the website is running tomcat because of directories like /manager.  

We can check the headers with curl:  
```
curl -I http://10.10.11.138/
```
![obraz](https://github.com/user-attachments/assets/fbdeb2ba-365e-4216-ab4a-7fc06120e697)

It returns with Java cookie which indicates that backend is written in Java.  
Tomcat is also written in Java meaning it's another hint.  
We can re-run feroxbuster with additional extensions and different list:  
```
feroxbuster --url http://10.10.11.138/ -x js,jsp,java,xml -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```
![obraz](https://github.com/user-attachments/assets/6da9c81a-f398-4eac-be41-438626053592)

It found index.jsp but nothing more of interest.  



## 403 bypass trick

If we go to /manager we get 403 access denied.  
There is a report written by Orange Tsai that is a must read if you didn't do it already:  
```
https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
```
I'll paste the part about tomcat here:  

![obraz](https://github.com/user-attachments/assets/815b0036-d80d-4262-814f-d6d2a8c43d4c)

It bypasses Tomcat’s path parsing and normalization logic.  

We can now access:  
```
http://<ip>/x/..;/manager
```
Luckily for us default credentials worked
+  tomcat:tomcat

![obraz](https://github.com/user-attachments/assets/a3030bff-0336-4526-89c6-a23499c5101e)



## Log4Shell - exploitation  

Given the name of the box there might be a log4shell vulnerability.  
















































