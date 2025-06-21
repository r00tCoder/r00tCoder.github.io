## HTB Unobtainium (Hard) - Writeup

Difficulty: Hard

Unobtainium was a creative and well-designed HTB box with a fun mix of web exploitation and container privilege escalation:  
Electron app reverse-engineered,  
Prototype pollution exploited for RCE,  
Kubernetes pod lateral movement for privesc.  

---

## Nmap 

#### The nmap scan revealed eight open ports:  
```
PORT      STATE  SERVICE     VERSION
22/tcp    open   ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp    open   http        Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Unobtainium
|_http-server-header: Apache/2.4.41 (Ubuntu)
2379/tcp  closed etcd-client
2380/tcp  closed etcd-server
8443/tcp  open   ssl/http    Golang net/http server
| ssl-cert: Subject: commonName=k3s/organizationName=k3s
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster.local, DNS:localhost, DNS:unobtainium, IP Address:10.10.10.235, IP Address:10.43.0.1, IP Address:127.0.0.1
| Not valid before: 2022-08-29T09:26:11
|_Not valid after:  2026-06-06T11:48:56
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 401 Unauthorized
|     Audit-Id: c6108c66-f049-49d3-b53c-8e587bab876c
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Fri, 06 Jun 2025 11:49:44 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   GenericLines, Help, LPDString, RTSPRequest, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 401 Unauthorized
|     Audit-Id: 5ffcd52c-16be-465c-b66c-501bddced8fb
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Fri, 06 Jun 2025 11:49:44 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   HTTPOptions: 
|     HTTP/1.0 401 Unauthorized
|     Audit-Id: e26d87f9-1ac3-4415-b15f-071a9c59c729
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Fri, 06 Jun 2025 11:49:44 GMT
|     Content-Length: 129
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|_http-title: Site doesn't have a title (application/json).
10250/tcp open   ssl/http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=unobtainium
| Subject Alternative Name: DNS:unobtainium, DNS:localhost, IP Address:127.0.0.1, IP Address:10.10.10.235
| Not valid before: 2022-08-29T09:26:11
|_Not valid after:  2026-06-06T11:48:57
10256/tcp closed unknown
31337/tcp open   http        Node.js Express framework
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.95%T=SSL%I=7%D=6/6%Time=6842D5DE%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,14A,"HTTP/1\.0\x20401\x20Unauthorized\r\nAudit-Id:\x205ff
SF:cd52c-16be-465c-b66c-501bddced8fb\r\nCache-Control:\x20no-cache,\x20pri
SF:vate\r\nContent-Type:\x20application/json\r\nDate:\x20Fri,\x2006\x20Jun
SF:\x202025\x2011:49:44\x20GMT\r\nContent-Length:\x20129\r\n\r\n{\"kind\":
SF:\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\"
SF:,\"message\":\"Unauthorized\",\"reason\":\"Unauthorized\",\"code\":401}
SF:\n")%r(HTTPOptions,14A,"HTTP/1\.0\x20401\x20Unauthorized\r\nAudit-Id:\x
SF:20e26d87f9-1ac3-4415-b15f-071a9c59c729\r\nCache-Control:\x20no-cache,\x
SF:20private\r\nContent-Type:\x20application/json\r\nDate:\x20Fri,\x2006\x
SF:20Jun\x202025\x2011:49:44\x20GMT\r\nContent-Length:\x20129\r\n\r\n{\"ki
SF:nd\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Fail
SF:ure\",\"message\":\"Unauthorized\",\"reason\":\"Unauthorized\",\"code\"
SF::401}\n")%r(FourOhFourRequest,14A,"HTTP/1\.0\x20401\x20Unauthorized\r\n
SF:Audit-Id:\x20c6108c66-f049-49d3-b53c-8e587bab876c\r\nCache-Control:\x20
SF:no-cache,\x20private\r\nContent-Type:\x20application/json\r\nDate:\x20F
SF:ri,\x2006\x20Jun\x202025\x2011:49:44\x20GMT\r\nContent-Length:\x20129\r
SF:\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"stat
SF:us\":\"Failure\",\"message\":\"Unauthorized\",\"reason\":\"Unauthorized
SF:\",\"code\":401}\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request")%r(RTSPRequest,67,"HTTP/1\.1\x20400
SF:\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n
SF:Connection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.
SF:1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=u
SF:tf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessio
SF:nReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/pl
SF:ain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Requ
SF:est")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request");
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


## Port 8443 - Api 

![obraz](https://github.com/user-attachments/assets/d9970976-d65f-4202-8811-2a948544bfad)

It runs an https api, and returns json saying that we're unauthorzied.  



## Port 80 - Website  

![obraz](https://github.com/user-attachments/assets/8688cac9-a1e4-460a-94e0-d5c791a7b8c6)

It offers three links to download an app.  
unobtainium_debian.zip, unobtainium_redhat.zip, and unobtainium_snap.zip  

I'll run feroxbuster first and then download unobtainium_debian.zip  
```
feroxbuster -u http://10.10.10.235
```
Nothing intresting, let's download an app to inspect it.  

![obraz](https://github.com/user-attachments/assets/a4a72f5e-2599-4cab-8ce4-370047a5b83c)

We will use ar command to pull contents from .deb package.  

![obraz](https://github.com/user-attachments/assets/d7762d45-5f82-41c5-8f91-36c0decc5928)

It unpacks a .deb file into its core components:  
control.tar.gz  (contains metadata, and a few more things)  
debian-binary  (in our case contains "2.0")  
data.tar.xz  (contains source code)  

Let's unpack control.tar.gz:  

![obraz](https://github.com/user-attachments/assets/cd0124c8-bea0-4bba-a944-4f8190b3c4de)

I wouldn't copy all files content here just postinst that gave us an important hint:  
postinst is a script that runs after installation.  
```
#!/bin/bash

# Link to the binary
ln -sf '/opt/unobtainium/unobtainium' '/usr/bin/unobtainium'

# SUID chrome-sandbox for Electron 5+
chmod 4755 '/opt/unobtainium/chrome-sandbox' || true

update-mime-database /usr/share/mime || true
update-desktop-database /usr/share/applications || true
```

It suggests that it is an electron app.  
Since this is ane electron app we will look for the .asar file which contains source code.   
```
find . -name *.asar
```
/opt/unobtainium/resources/app.asar  



















