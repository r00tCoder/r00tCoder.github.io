## HTB Dab (Hard) - Writeup

Difficulty: Hard

Initial foothold was gained by fuzzing cookie names and values, leading to the discovery of a hidden authentication mechanism and access to restricted functionality.
An exposed Memcached instance was exploited to extract sensitive data, including valid credentials.
Privilege escalation was achieved via shared library hijacking in a misconfigured SUID binary, allowing execution of arbitrary code with root privileges.

---

## Nmap 

#### The nmap scan revealed four open ports:  

![obraz](https://github.com/user-attachments/assets/c4950260-c4fd-41c4-afb0-e91f06fd36e9)


## Port 21 - FTP

I'll start with ftp as I often do when it's open on CTF's.   
We can login with username "anonymous" and a blank password "".  

![obraz](https://github.com/user-attachments/assets/f83e2c35-5262-4c7f-9da8-79d3435bac24)

There is only one file and it is a .jpg photo.  
I'll transfer it with GET command.  

![obraz](https://github.com/user-attachments/assets/e7ccdb0d-e783-4f67-ae5e-ab58e138c430)

First I will check metadata with exiftool.  

![obraz](https://github.com/user-attachments/assets/6c1b7327-d90e-4108-b35d-7afc97dfe946)

Nothing intresting there.  

Steganography is a way to hide secret information or even entire files inside normal files, like images or audio.  
For example, a document can be hidden inside a photo without visibly altering the image.    
We will now look for hidden files.  

![obraz](https://github.com/user-attachments/assets/55d6818b-6635-4836-bbed-7f1b4101d692)  

There is a hidden file but it's just a rabbit hole.  


## Port 80 - Website 

![obraz](https://github.com/user-attachments/assets/16c059f8-bb7e-4fa5-ad3a-5894894f98f3)

Website contains login page, default credentials didin't work.  
We can try a bruteforce attack, normally we would bruteforce usernames first but I'll just guess that there is an admin account:  

![obraz](https://github.com/user-attachments/assets/f6756c03-7f21-4201-a661-787190d0bce1)

We got valid credentials.  
Let's use them to login to the website.  

![obraz](https://github.com/user-attachments/assets/b71def5c-cc04-437d-9217-2e4aefd926a8)

It doesn't contain anything intresting, we will now move to port 8080 and maybe comeback to port 80 later.  



## Port 8080 - Second Website 

![obraz](https://github.com/user-attachments/assets/0758865b-4bd6-46f0-b67a-0e77f355dfe7)

It gives us "Access Denied" but also a hint that there is a cookie that could give us more access.  
We will perform Fuzzing on the Cookie name:  

![obraz](https://github.com/user-attachments/assets/142ee62c-1185-474f-83e6-c73cfc438a4f)

After running it for the first time we noticed that everything returns 30 W, meaning we need to us --hw 30 to filter it out as shown above.  

We've successfully found a cookie name, we can try bruteforcing it with the same tool.  
We will use a list from seclists containing parameter names.  

![obraz](https://github.com/user-attachments/assets/628e7d54-2d2e-4606-98a9-a93b2f99c1fd)  

Now we have both cookie name and it's value.  
We will now open developer tools with F12 and add a cookie called "password" with a value "secret".  

![obraz](https://github.com/user-attachments/assets/b744e9a6-bdf9-4bd5-8343-ec23d909aad8)

Now when we refresh the page we get more access.  

![obraz](https://github.com/user-attachments/assets/c9c77166-364d-44e1-a79e-fbb5ee772f81)  

It's a TCP socket test site.  
We can specify a port and a line to send.   
I'll try some basic command injection.  

![obraz](https://github.com/user-attachments/assets/d42ba6b0-7c6d-4c90-957d-8c5b036dd835)

Unfortunately it has a filter for that.  

![obraz](https://github.com/user-attachments/assets/014dd68e-0091-405c-997f-d8456837c02e)  

After looking at how this web app behaves we notice that it gives "500 internal server error" for non-listening ports.  
I'll use wfuzz again to check for other open ports that may be working locally that we weren't able to talk to before.  
First let's create a list for all port numbers.  

![obraz](https://github.com/user-attachments/assets/17dc7aeb-ad95-480d-a617-d37a67f6652c)  

And now use it with wfuzz and filter out http code 500:  

![obraz](https://github.com/user-attachments/assets/fa89e066-67ef-4ba0-a10e-33a7afb26ec8)

We have found port 11211.  
it's used for memcached - "a high-performance, distributed memory object caching system."    
It's designed to speed up web apps by caching frequently accessed data.  


## Memcached - Port 11211  

I had to google a cheatsheet with memcached commands to enumerate it.  
This article contains everything we would need:  
```
https://www.hackingarticles.in/penetration-testing-on-memcached-server/
```
We can start with enumerating version:  

![obraz](https://github.com/user-attachments/assets/4ce6b5b3-c9b9-44ba-a6d9-5c897553b8bc)

It worked, now we can look for info about items cached in memory.  
Notice that we need to login as admin on port 80 to get this info because caching times out.  

![obraz](https://github.com/user-attachments/assets/e420b050-5e5f-49dc-8cf9-076faf669ea2)

We have two active slabs as shown above, slab with ID 16 and slab with ID 26.  
The first one is nothing important just the contents that are on the website on port 80.  
Let's check the second slab.  

![obraz](https://github.com/user-attachments/assets/4fe3b265-e4f5-4c5c-a09e-a1d78b962337)

Using stats cachedump, 26 = ID, 0 = keys we want (zero means all keys).  
We can see that there is ITEM called users, that seems intresting.  

![obraz](https://github.com/user-attachments/assets/52a7ef44-53e9-4709-8326-f51e96e55e19)

It dumped usernames with it's hashes.  
all we need to do is put them in a file and run hashcat with mode 0 for md5.  
```
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

After it run we can use --show to see all hashes that successfully cracked.  

![obraz](https://github.com/user-attachments/assets/43aedcc5-7b3f-4faf-bbb9-322c0ec938b9)

We can take hashes, match them with usernames and put it in a file.  


![obraz](https://github.com/user-attachments/assets/6cd1043a-38fd-4ec4-b789-4cf7b0049cfd)

Now as we have this file we can try to login with ssh using hydra.  

![obraz](https://github.com/user-attachments/assets/ccf48ca0-a7c5-4013-b50f-e9f5d83e4527)

-C flag is for a file that has usernames and passwords combined.  




## Shell as genevieve

We can now login with ssh:  

![obraz](https://github.com/user-attachments/assets/09cf6974-0074-42b3-a23c-cc2848dce013)




## Priv esc to root

After running linpeas we have found two SUID binaries.  

![obraz](https://github.com/user-attachments/assets/91ac404c-b839-4cfd-8bb8-2b89321c22a3)

/sbin/ldconfig  
and  
/usr/bin/myexec  

Let's check myexec first.  

![obraz](https://github.com/user-attachments/assets/0845bec8-a7f4-46fb-9bcf-197e589fdebf)

It just asks for a password.  
we can use ltrace to check interactions with shared libraries.  

![obraz](https://github.com/user-attachments/assets/06830328-0099-4bbf-8052-a30471d93bb6)

This is a line where this binary compare password specified to the real password:  
```
strcmp("s3cur3l0g1n", "test")
```
Meaning we now have a correct password "s3cur3l0g1n".  

Now we can check what happens when we use correct password:  

![obraz](https://github.com/user-attachments/assets/b84b4fa8-d1ec-4657-a4ac-eddbf898d77c)



## Exploiting SUID binary

We have SUID bit set in ldconfig also which is a tool used to link libraries.  
Let's trace system calls when we run this app by using strace command:   

![obraz](https://github.com/user-attachments/assets/7385950a-a7b4-4345-a3a0-3b32d620f70a)

From the output we notice that it loads custom share library called  /usr/lib/libseclogin.so  
It could be done with ldd which will also be a more clear way.  

![obraz](https://github.com/user-attachments/assets/23211668-1bec-48ac-93c6-f65ced67d6dc)

ldd prints shared libraries use by a program.  

We have ldconfig with SUID bit set, meaning we can try to hijack a shared library.  
First we need to create a new shared library.  
I'll create a new directory first /tmp/hijack.  

Now we can create libseclogin.c there. here is an exemplary code:  
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void pwn() {
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
```

Now we need to compile it:

![obraz](https://github.com/user-attachments/assets/baa27584-8e9f-4f15-80e9-dd7adb6eb729)

We end up with /tmp/hijack/libseclogin.so 

ldconfig uses files in /etc/ld.so.conf.d/ directory to determine which libraries it will load.  
We can now just simply create new file with our /tmp/hijack path specified.  

![obraz](https://github.com/user-attachments/assets/eab7efc9-11de-4b86-a128-7f994d3bd398)

Now if we run ldconfig it will update a path, it can be verified simply by using ldd again.  

![obraz](https://github.com/user-attachments/assets/c0a93ec9-b4bb-4c50-affb-bf6c40b92c9d)

Now when we run myexec binary it should load our malicious shared library instead and execute it with root privileges (since we have SUID bit set).  

![obraz](https://github.com/user-attachments/assets/9598438b-eb92-426a-8b91-baffaa088128)

It worked, thank you for reading. 





































