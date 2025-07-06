---
layout: post
title: "HTB Sandworm (Medium) - Writeup"
date: 2025-07-02
tags: [HTB, CTF, privilege-escalation, GPG, Firejail]
---


## HTB Sandworm (Medium) - Writeup

Difficulty: Medium  

This box revolves around a Flask web app with GPG-based functionality.  
By injecting SSTI payloads via GPG key names and signature verification, we achieve RCE.  
Enumeration reveals credentials and a Rust binary (tipnet) run via cron as root, which imports a custom logger crate we can write to—allowing for privilege escalation.  
Finally, we exploit a known Firejail vulnerability (CVE-2022-31214) to escalate to root.  

---

## Nmap 

#### The nmap scan revealed three open ports:  
asd
sasad
afsafs
