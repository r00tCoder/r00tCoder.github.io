## HTB Object - Writeup

Difficulty: Hard

This Active Directory box was especially challenging due to a firewall that blocked many connections, adding an extra layer of difficulty.  
The journey began with decrypting a password from Jenkins, which granted WinRM access as a user.  
From there, abusing ACLs became crucial for escalating privileges.  
Each step deepened my understanding of AD exploitation, making it a rewarding and insightful challenge.  

---

## Nmap 

#### The nmap scan revealed three open ports:

![obraz](https://github.com/user-attachments/assets/efd1d3c9-feb6-4852-9cbe-d5584e14695f)


## Port 80 - Website 

Here’s what the website looks like:

![obraz](https://github.com/user-attachments/assets/282f048d-8c09-46d6-a32a-b91705981b8f)

Right from the initial enumeration, an email address and domain name are revealed.  
Let’s make a note of the email for later and add the domain **object.htb** to /etc/hosts.  
At this point, we can try directory busting, but it didn’t yield any results.  

Lastly there is a link that points to **http://object.htb:8080/**.
  
  
  
  

## Port 8080 - Jenkins

This website hosts a Jenkins instance.  
We can try common default credentials such as admin:password, jenkins:jenkins, and similar combinations, but they didn't work.


<p align="center">
  <img src="https://github.com/user-attachments/assets/3d1d8667-bbe8-443d-a48c-753cf09f64e4" alt="obraz">
</p>

After creating an account, we gain access to the dashboard and notice it’s running version 2.317 of Jenkins.  
We could potentially abuse the Script Console using a Groovy-based reverse shell, but access to it requires administrative privileges.  
My second thought was to create a Jenkins job that, when built, executes a Windows command, eventually leading to shell access.  
This is a popular way to execute commands in Jenkins, let's try that:

**Click on "New Item" -> "Freestyle Project", and scroll a bit down, and select "Build Periodically":**

![obraz](https://github.com/user-attachments/assets/0c054a9e-f114-4899-af57-3065f08fd866)


We want it to make a build every minute, meaning our command will be executed every minute also.  
**Scroll a bit down and "Add a build step" -> "Execute Windows Batch Command"**


![obraz](https://github.com/user-attachments/assets/6185423b-29c0-4afa-9990-8695048807fa)  
Then hit save and apply.

Now we wait for one minute and select: 
**last build -> console output -> check if we have command execution**

![obraz](https://github.com/user-attachments/assets/3e220dc1-4faf-4b76-9003-3df418ff247c)  

Now it's time to upload a reverse shell to the target machine, but here we discovered that it won't be possible likely to the firewall settings that block outbound connection.

![obraz](https://github.com/user-attachments/assets/8aede77d-3c9a-4342-869f-d85dca9cbb83)  

It's time to change approach, we're left with possibility to enumerate the target system.  
First we want to check jenkins home directory.  
We'll exeucte:  

![obraz](https://github.com/user-attachments/assets/36eec344-454a-4133-a86b-55b9f2a57853)

Output:

![obraz](https://github.com/user-attachments/assets/7faa5c88-58fe-4b35-a867-57c020e7bc85)

We've got two intresting directories: secrets, and users.  
First we'll check Users directory.  

![obraz](https://github.com/user-attachments/assets/b55729d4-5bdb-43fd-ac35-7ce8411f697c)

There is a user that we created previously and admin.  
Let's check admin directory:  

![obraz](https://github.com/user-attachments/assets/5055b9c1-1fad-4a15-b694-7007a7f8174c)  

We have a config file, lets see what's in it:  

![obraz](https://github.com/user-attachments/assets/cb7ee68e-4fe9-4132-80f2-e937b572e851)


File Contents:  
```
<?xml version='1.1' encoding='UTF-8'?>
<user>
  <version>10</version>
  <id>admin</id>
  <fullName>admin</fullName>
  <properties>
    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@2.6.1">
      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash">
        <entry>
          <com.cloudbees.plugins.credentials.domains.Domain>
            <specifications/>
          </com.cloudbees.plugins.credentials.domains.Domain>
          <java.util.concurrent.CopyOnWriteArrayList>
            <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
              <id>320a60b9-1e5c-4399-8afe-44466c9cde9e</id>
              <description></description>
              <username>oliver</username>
              <password>{AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=}</password>
              <usernameSecret>false</usernameSecret>
            </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
          </java.util.concurrent.CopyOnWriteArrayList>
        </entry>
      </domainCredentialsMap>
    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>
    <hudson.plugins.emailext.watching.EmailExtWatchAction_-UserProperty plugin="email-ext@2.84">
      <triggers/>
    </hudson.plugins.emailext.watching.EmailExtWatchAction_-UserProperty>
    <hudson.model.MyViewsProperty>
      <views>
        <hudson.model.AllView>
          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>
          <name>all</name>
          <filterExecutors>false</filterExecutors>
          <filterQueue>false</filterQueue>
          <properties class="hudson.model.View$PropertyList"/>
        </hudson.model.AllView>
      </views>
    </hudson.model.MyViewsProperty>
    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.3.5">
      <providerId>default</providerId>
    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>
    <hudson.model.PaneStatusProperties>
      <collapsed/>
    </hudson.model.PaneStatusProperties>
    <jenkins.security.seed.UserSeedProperty>
      <seed>ea75b5bd80e4763e</seed>
    </jenkins.security.seed.UserSeedProperty>
    <hudson.search.UserSearchProperty>
      <insensitiveSearch>true</insensitiveSearch>
    </hudson.search.UserSearchProperty>
    <hudson.model.TimeZoneProperty/>
    <hudson.security.HudsonPrivateSecurityRealm_-Details>
      <passwordHash>#jbcrypt:$2a$10$q17aCNxgciQt8S246U4ZauOccOY7wlkDih9b/0j4IVjZsdjUNAPoW</passwordHash>
    </hudson.security.HudsonPrivateSecurityRealm_-Details>
    <hudson.tasks.Mailer_-UserProperty plugin="mailer@1.34">
      <emailAddress>admin@object.local</emailAddress>
    </hudson.tasks.Mailer_-UserProperty>
    <jenkins.security.ApiTokenProperty>
      <tokenStore>
        <tokenList/>
      </tokenStore>
    </jenkins.security.ApiTokenProperty>
    <jenkins.security.LastGrantedAuthoritiesProperty>
      <roles>
        <string>authenticated</string>
      </roles>
      <timestamp>1634793332195</timestamp>
    </jenkins.security.LastGrantedAuthoritiesProperty>
  </properties>
</user>
```

This is a file that contain credentials and can be decrypted with a python script, but in order to do that we will need master.key and hudson.util.Secret which both can be found in **Secrets** directory.  

![obraz](https://github.com/user-attachments/assets/0fe4e98d-2575-4692-88d6-38103fadfe5c)

Output:  

![obraz](https://github.com/user-attachments/assets/e69f3363-d8b0-41ef-aef2-0346995f52b0)

We will copy this key to our kali linux.  
With getting hudson.util.Secret I had a problem but finally it worked when converted to base64 with powershell:  

![obraz](https://github.com/user-attachments/assets/0f7bdf6e-0df1-4cfb-9f45-6f9f03e80509)

Output:

![obraz](https://github.com/user-attachments/assets/415ba5c2-ea76-4dd2-86bc-6ebb84ebe281)

Now let's decode that and put in a file:  

![obraz](https://github.com/user-attachments/assets/19ae2ea9-21d9-435f-a710-c8b3d0857ad4)

Now we can put everything together and get plain text password with this script:

```
https://github.com/gquere/pwn_jenkins/blob/master/offline_decryption/jenkins_offline_decrypt.py
```

![obraz](https://github.com/user-attachments/assets/aa5be5f5-2be8-409d-b5e8-ae0ef4e4449e)  

From nmap scan we know that port 5985 is open, meaning that we can try connect with evil-winrm:  

![obraz](https://github.com/user-attachments/assets/51ac9437-f71d-4a77-876e-72272f9c03ff)  

Let's retrieve a flag:  

![obraz](https://github.com/user-attachments/assets/06b50265-e37a-4be9-b2f9-e4f0f237b5d6)


I like to check privileges first when enumerating windows:  

![obraz](https://github.com/user-attachments/assets/3434ce35-7525-4ea9-8844-2faae78d7745)


At this point I'll run bloodhound.  
Normally I would run bloodhound-python to collect information for bloodhound but there is a firewall that blocks connection.  
We can use evil-winrm's upload function to upload Sharphound, and run it with collection method "all":

![obraz](https://github.com/user-attachments/assets/b2a5220f-8078-40cd-8817-9bace22481dc)


Now we can move .zip file with evil-winrm's download function, run bloodhound and ingest data.  


## Bloodhound Analysis  

First we can mark oliver as "owned".  
If we look at node info and scroll a bit down we notice that oliver has one Object control.




<p align="center">
  <img src="https://github.com/user-attachments/assets/f54f92f7-dade-40b7-9933-388f5a3ad325" alt="obraz">
</p>

If we check that we can see that we have "ForceChangePassword" over user smith.  
Meaning we can change smith's password, normally I would do it remotely from kali linux, but once again this machine blocks connections with firewall.  

![obraz](https://github.com/user-attachments/assets/d66306c4-8b48-4e3a-8847-040e72404f0f)

Let's change his password locally on the target machine, in order to do that we will use PowerView.ps1 script.
We can upload it with evil-winrm's upload function and load it into memory.  

![obraz](https://github.com/user-attachments/assets/80c09be8-be7d-4851-b26f-e9e7896bf116)

Now to change his password we need to create password object in powershell which will contain new password for user smith.  
Then use this object to change the password.  

![obraz](https://github.com/user-attachments/assets/9778af70-f5f6-485c-91e7-6f8073625011)  


## Shell as Smith

Now we can login with evil-winrm.  

![obraz](https://github.com/user-attachments/assets/3a8155fa-c4c0-4992-b959-f507a24cf213)



## Pivoting to Maria

Back to bloodhound we can mark smith as owned.  
Lucky for us smith has object control over another user too. 

![obraz](https://github.com/user-attachments/assets/da8ba73e-7e26-406a-a31e-2462447123f2)

Bloodhound help says that we can perform targeted Kerberoast attack with "GenericWrite" privilege.  
To achieve it we need to create SPN for the target user, and then retrieve it's hash.  

![obraz](https://github.com/user-attachments/assets/e30c420a-3d49-4677-b53d-08a4d81beaad)

Unfortunately it didnt't work.  

![obraz](https://github.com/user-attachments/assets/a75f8780-e281-4f6f-9dab-3dabe3fd1307)

It's time for different approach, let's open google and do more research.  
After researching this topic I found that we can change logonscript for a user with "GenericWrite" privilege.  

```
https://notes.morph3.blog/abusing-active-directory-acls/genericwrite
```
This article explains it.  
Logon script runs everytime a user logs in.  
It's automated by HTB but normally we would wait for a user to log in.   

Due to firewall we can't connect back to our machine, let's stick with enumeration.  

![obraz](https://github.com/user-attachments/assets/2b31fb66-30fc-4a67-9ef7-58c063cce9c1)  

On this screenshot we can see that user Maria has Engines.xls file on the desktop.  
We can copy this file to programdata directory with the same method.  

![obraz](https://github.com/user-attachments/assets/30371752-072b-49d4-98a5-6fda16254755)

Let's check this file:  

![obraz](https://github.com/user-attachments/assets/9198e3dc-0366-49a6-a0b2-d95c53bd9172)  

It contain some passwords, now I'll put those passwords in a file and spray them with nxc:  

![obraz](https://github.com/user-attachments/assets/13a1e350-81d0-499b-92c4-8324004ad961)  



## Elevating Privileges as Maria

Now we can check bloodhound once again.  
We have WriteOwner over "Domain Admins" group, meaning we can easily elevate privileges.  

First we will take ownership of this group:
```
Set-DomainObjectOwner -Identity 'Domain Admins' -OwnerIdentity 'maria'
```
Then grant Maria full rights:
```
Add-DomainObjectAcl -Rights 'All' -TargetIdentity "Domain Admins" -PrincipalIdentity "maria"
```
Lastly add Maria to the group:
```
Add-ADGroupMember -Identity 'Domain Admins' -Members 'maria'
```

![obraz](https://github.com/user-attachments/assets/1d5a12aa-1de5-4929-9180-eb4f671b05b7)  

For it to take changes we have to exit evil-winrm and connect again.  
Lastly we will retrieve the root flag.  

![obraz](https://github.com/user-attachments/assets/cbd67214-a04f-4e14-9504-803c9a450b0d)
