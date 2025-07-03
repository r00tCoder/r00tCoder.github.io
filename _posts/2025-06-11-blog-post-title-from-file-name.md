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




















































