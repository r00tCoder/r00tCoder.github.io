## HTB Sandworm (Medium) - Writeup

Difficulty: Medium

This box revolves around a Flask web app with GPG-based functionality.  
By injecting SSTI payloads via GPG key names and signature verification, we achieve RCE.  
Enumeration reveals credentials and a Rust binary (tipnet) run via cron as root, which imports a custom logger crate we can write to—allowing for privilege escalation.  
Finally, we exploit a known Firejail vulnerability (CVE-2022-31214) to escalate to root.  

---

## Nmap 

#### The nmap scan revealed three open ports:  

![obraz](https://github.com/user-attachments/assets/f64289ac-22cf-4e03-8e80-8c45e9321d41)  


## Port 80 - Website  

This website just redirects to httpsL//ssa.htb  
We'll add it to /etc/hosts and move to 443  



## Port 443 - https website  

![obraz](https://github.com/user-attachments/assets/46fd1c0b-d1ad-4212-b0b6-24db7e905246)  

After quick enumeration I found that this app is written in flask.  
The site exposes three main routes:  

+  /contact
+  /pgp
+  /guide

/pgp contains pgp key, first thing that came to my mind is to import it to kali.  
It can be done by putting it in a file and using:  
```
gpg --import key
```
![obraz](https://github.com/user-attachments/assets/557ef4a9-d850-46b5-8f67-f8acbc623bde)

Now we will be able to encrypt messages with this key.  
On the contact page we can send encrypted messages:  

![obraz](https://github.com/user-attachments/assets/3cde4962-4abd-4770-a569-153e8727bfc4)

On the guide page there are three functionalities:  
+  Decrypting
+  Encrypting
+  Verifying Signatures

Let's test them one by one starting with Decryption.  
Our goal is to observe how this site works to look for anything that might be abused.  

It can be encrypted with the following command:  
```
gpg --armor --recipient atlas@ssa.htb --encrypt message.txt -o -
```

![obraz](https://github.com/user-attachments/assets/94b3c21b-dbf1-4b70-8d03-5bc6bf9c7c39)

We can now paste this message and click on "Decrypt".  

![obraz](https://github.com/user-attachments/assets/15b62683-bf4e-4ab7-84a9-228936d57492)

It just decrypts but there is nothing unusual.  

The second section of the site allows us to provide our public key, and it responds with a message encrypted using that key.  
For it to work we need to generate a key:  
```
gpg --full-key-gen
```
It will prompt with some questions, go with any values you like doesn't matter.  

![obraz](https://github.com/user-attachments/assets/ed288c89-4d7d-4e8d-bfd2-26be4f7b36dd)

Site allows us to paste the key, for that we need to print it with coresponding key ID:  
```
gpg --armor --export B8A1EE1855AA25C45247A84A3B30A676B4804748 
```
![obraz](https://github.com/user-attachments/assets/e2645220-4377-4390-89a5-e1d66039a48b)


Now if we paste this key they will use it to decrypt some message:  

![obraz](https://github.com/user-attachments/assets/7da727ae-2e57-4ad6-b6a7-dc2a1aca876d)  

We can copy it and decrypt because we own the key:  
```
gpg --decrypt msg.txt
```

![obraz](https://github.com/user-attachments/assets/fa9eb5f2-1da1-454f-be7f-4e0dfab3f960)

Nothing unusual so far.  

Third and last section allows to verify a signature.  
With pgp we can sign a message, let's do it:  

![obraz](https://github.com/user-attachments/assets/7ffdb0b3-5c0f-4146-b474-73a584a6e64f)


Now signature will be save into test.txt.asc:  

![obraz](https://github.com/user-attachments/assets/e56b426e-16c3-448e-8d07-55c22587a8a6)

If we paste the key and the signature into the site and click on verify signature we get:  

![obraz](https://github.com/user-attachments/assets/52aea4bb-433b-4a03-85c4-ec91254417f6)

And now is is something very intresting.  
It uses most likely some templating engine.  
There is possibility that it will contain SSTI vulnerability.  

Now we want to look for a parameter that is being generated and that we control.  
In this case template contains key name that we control when generating a key:  

![obraz](https://github.com/user-attachments/assets/2738ee0f-ecf9-47f2-8bf9-de1e5ded5a49)


## SSTI - exploitation  

First we need to verify if it's vulnerable with a poc payload.  
Previously we generated a key with full generation command, but there is an option to generate it faster:  
```
gpg --quick-generate-key "{{7*7}}" default default never
```
![obraz](https://github.com/user-attachments/assets/317c2949-cc4f-4f23-a373-7c49353dde0e)  

Now we need to create a message and export the key:  
```
echo "malicious" > text
gpg --armor --export 24A027F729D76AEE8DE74EEEFD61AF656FB0700A
```

![obraz](https://github.com/user-attachments/assets/6a7df3d1-fed6-4d61-b1b5-fadf944cd8de)  

After that we want to sign a message and export it's signature:  
```
gpg --local-user 24A027F729D76AEE8DE74EEEFD61AF656FB0700A --clearsign text
cat text.asc
```
![obraz](https://github.com/user-attachments/assets/2089bbb7-eeea-4f14-b06a-149c58f0cc21)

Now paste both of then into the site and click "Verify Signature".  

![obraz](https://github.com/user-attachments/assets/a8b189e1-ae41-4f32-8373-38bbb72e3e07)

It performed multiplication which means that the templating engine is vulnerable to SSTI.  

Before we test for code execution we can dump the config:  
```
{% raw %}
gpg --quick-generate-key "{{ config }}" default default never
{% endraw %}
```




























































