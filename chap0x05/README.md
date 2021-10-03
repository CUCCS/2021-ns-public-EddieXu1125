# 网络安全第五章实验

## 基于 Scapy 编写端口扫描器

---

## 实验目的

掌握网络扫描之端口状态探测的基本原理

---

## 实验环境

- Python **3.9.2**
- scapy **2.4.4**
- nmap **7.90**
- 实验拓扑环境
  ![](./img/tuopu.png)

---

## 实验要求

- [x] 禁止探测互联网上的 IP ，严格遵守网络安全相关法律法规
- [x] 完成以下扫描技术的编程实现
  - [x] TCP connect scan / TCP stealth scan
  - [x] TCP Xmas scan / TCP fin scan / TCP null scan
  - [x] UDP scan

- [x] 上述每种扫描技术的实现测试均需要测试端口状态为：开放、关闭 和 过滤 状态时的程序执行结果
- [x] 提供每一次扫描测试的抓包结果并分析与课本中的扫描方法原理是否相符？如果不同，试分析原因；
- [x] 在实验报告中详细说明实验网络环境拓扑、被测试 IP 的端口状态是如何模拟的
- [x] （可选）复刻 nmap 的上述扫描技术实现的命令行参数开关

---

## 先验知识

1. TCP connect scan 

> 这种扫描方式可以使用 Connect()调用，使用最基本的 TCP 三次握手链接建立机制，建立一个链接到目标主机的特定端口上。首先发送一个 SYN 数据包到目标主机的特定端口上，接着我们可以通过接收包的情况对端口的状态进行判断。
 
三种情况下的不同响应：

- 接收 SYN/ACK 数据包，说明端口是开放状态的；
- 接收 RST/ACK 数据包，说明端口是关闭的并且链接将会被重置；
- 目标主机没有任何响应，意味着目标主机的端口处于过滤状态。

> 若接收到 SYN/ACK 数据包（即检测到端口是开启的），便发送一个 ACK 确认包到目标主机，这样便完成了三次握手连接机制。成功后再终止连接。

[TCP标志位详解（TCP Flag）](https://blog.csdn.net/ChenVast/article/details/77978367)


2. TCP SYN scan
   
> 与 TCP Connect 扫描不同，TCP SYN 扫描并不需要打开一个完整的链接。发送一个 SYN 包启动三方握手链接机制，并等待响应。

三种情况下的不同响应：

- 接收到一个 SYN/ACK 包，表示目标端口是开放的；
- 接收到一个 RST/ACK 包，表明目标端口是关闭的；
- 没有响应，说明端口是被过滤的状态。

> 当得到的是一个 SYN/ACK 包时通过发送一个 RST 包立即拆除连接。

3. TCP Xmas scan

> Xmas 发送一个 TCP 包，并对 TCP 报文头 FIN、URG 和 PUSH 标记进行设置。

- 若是关闭的端口则响应 RST 报文；
- 开放或过滤状态下的端口则无任何响应
  
> 优点是隐蔽性好，缺点是需要自己构造数据包，要求拥有超级用户或者授权用户权限。


4. TCP fin scan 
  
> 仅发送 FIN 包，它可以直接通过防火墙.

- 如果端口是关闭的就会回复一个 RST 包
- 如果端口是开放或过滤状态则对 FIN 包没有任何响应。

> 其优点是 FIN 数据包能够通过只监测 SYN 包的包过滤器，且隐蔽性高于 SYN 扫描。缺点和 SYN 扫描类似，需要自己构造数据包，要求由超级用户或者授权用户访问专门的系统调用。



5. TCP null scan

> 发送一个 TCP 数据包，关闭所有 TCP 报文头标记。

- 只有关闭的端口会发送 RST 响应。
  
> 其优点和 Xmas 一样是隐蔽性好，缺点也是需要自己构造数据包，要求拥有超级用户或者授权用户权限。



6. UDP scan

> UDP 是一个无链接的协议，当我们向目标主机的 UDP 端口发送数据,我们并不能收到一个开放端口的确认信息,或是关闭端口的错误信息。

- 如果收到一个 ICMP 不可到达的回应，那么则认为这个端口是关闭的
- 对于没有回应的端口则认为是开放的，但是如果目标主机安装有防火墙或其它可以过滤数据包的软硬件,那我们发出 UDP 数据包后,将可能得不到任何回应,我们将会见到所有的被扫描端口都是开放的。

UDP扫描比较简单，一般如果返回ICMP port unreachable说明端口是关闭的，而如果没有回应或有回应(有些UDP服务是有回应的但不常见)则认为是open，但由于UDP的不可靠性，无法判断报文段是丢了还是没有回应，**所以一般扫描器会发送多次**，然后根据结果再判断。这也是为什么UDP扫描这么慢的原因。


---
## 环境配置

1. 配置端口开放状态
   
  ```
  使用以下命令开启80端口：
  nc -l -p 80
  使用以下命令查看端口开放情况：
  netstat -ntlp #查看使用tcp协议端口情况
  netstat -nulp #查看使用udp协议端口情况
  ``` 
  也可以通过使用某种服务开启端口
  ```
  比如通过开启dnsmasq服务来开启53端口
  systemctl start dnsmasq.service
  ```


2. 使用以下命令进行端口的过滤设置
  
  ```
  iptables -n -L
  # 查看本机关于IPTABLES的配置 以列表的形式显示出当前使用的 iptables 规则，并不做解析

  iptables -A INPUT -p tcp --dport 80 -j REJECT
  # -A 将规则添加到默认的 INPUT（入站）链的末尾的操作指令
  # -p 指定特定的协议
  # --dport 目的端口号

  iptables -t filter -F
  -t filter：对过滤表进行操作，用于常规的网络地址及端口过滤。
  -F：清空列表中的所有规则。
  ```



## 实验过程

1. TCP connect scan / TCP stealth scan

    **TCP connect scan**

![](./img/tcp-connect-scan.png)


TCP connect scan 与 TCP stealth scan 均将flags字段设置为2，或者是“S”。

两者效果是一样的，都是发送SYN包。

- 代码实现

```py
import logging
from scapy.all import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

dst_ip = "172.16.111.132"
src_port = RandShort()
dst_port = 80

print('TCP connect scan:')
print('-----------------------------------------')
tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
print('-----------------------------------------')


if(str(type(tcp_connect_scan_resp))=="<class 'NoneType'>"):
    print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Closed")
elif(tcp_connect_scan_resp.haslayer(TCP)):
    if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):       
        send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
        print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Open")
    elif(tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
        # 
        print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Closed")
elif(tcp_connect_scan_resp.haslayer(ICMP)):
    if(int(tcp_connect_scan_resp.getlayer(ICMP).type)==3 and int(tcp_connect_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
        print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Filtered")


```


- 效果展示
  
  - 端口关闭时：
  
  ![](./img/tcp-connect-close.png)
  
  - 端口开放时：
  
  ![](./img/tcp-connect-open.png)
  
  - 端口过滤时：
  
  ![](./img/filter-port.png)
  ![](./img/tcp-connect-filtered.png)

- 效果分析
  与课本预期相符

**注： 以下的nmap复刻只截取了三种情况下的某一种，由于情况太多，不一一截取，但是使用的命令都已敲出。**
- 使用 `nmap` 实现同样功能
  ```bash
  nmap -sT -p 80 172.16.111.132
  ```
  ![](./img/nmap-tcp-connect-scan.png)

  还发现nmap无法识别端口被过滤的情况


    
**TCP stealth scan**

![](./img/tcp-syn-scan.png)

- 代码实现

```python
import logging
from scapy.all import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

dst_ip = "172.16.111.132"
src_port = RandShort()
dst_port=80

print('TCP stealth scan:')
print('-----------------------------------------')
stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
print('-----------------------------------------')

if(str(type(stealth_scan_resp))=="<class 'NoneType'>"):
    print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Filtered")
elif(stealth_scan_resp.haslayer(TCP)):
    if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
        send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=10)
        print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Open")
    elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
        print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Closed")
elif(stealth_scan_resp.haslayer(ICMP)):
    if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
        print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Filtered")
```


- 效果展示：
  - 端口关闭时： 
  ![](./img/tcp-syn-scan-closed.png)
  - 端口开启时：
  ![](./img/tcp-syn-scan-open.png)
  - 端口过滤时：
  ![](./img/tcp-syn-scan-filtered.png)

- 效果分析
  与课本预期相符

- 使用 `nmap` 实现同样功能
```bash
nmap -sS -p 80 -n -vv 172.16.111.132
```

![](./img/nmap-tcp-syn-scan-open.png)

2. TCP Xmas scan / TCP fin scan / TCP null scan

**TCP Xmas scan**

![](./img/tcp-xmas-scan.png)

- 代码实现

```py
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

dst_ip = "172.16.111.132"
src_port = RandShort()
dst_port = 80

print('TCP xmas scan:')
print('-----------------------------------------')
xmas_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="FPU"),timeout=10)
print('-----------------------------------------')

if (str(type(xmas_scan_resp))=="<class 'NoneType'>"):
    print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Filtered or Open")
elif(xmas_scan_resp.haslayer(TCP)):
    if(xmas_scan_resp.getlayer(TCP).flags == 0x14):
        print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Closed")
elif(xmas_scan_resp.haslayer(ICMP)):
    if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
        print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Filtered")

```


- 效果展示：
  - 端口关闭时： 
  ![](./img/tcp-xmas-scan-closed.png)
  - 端口开启时：
  ![](./img/tcp-xmas-scan-open.png)
  - 端口过滤时：
  ![](./img/tcp-xmas-scan-filtered.png)

- 效果分析
  与课本预期相符

- 使用 `nmap` 实现同样功能
  ```bash
  nmap -sX -p 80 -n -vv 172.16.111.132
  ```

  ![](./img/nmap-tcp-xmas-scan-filtered.png)


**TCP fin scan**

![](./img/tcp-fin-scan.png)

- 代码实现

```py
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "172.16.111.132"
src_port = RandShort()
dst_port = 80

print('TCP fin scan:')
print('-----------------------------------------')
fin_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="F"),timeout=10)
print('-----------------------------------------')

if (str(type(fin_scan_resp))=="<class 'NoneType'>"):
    print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Filtered or Open")
elif(fin_scan_resp.haslayer(TCP)):
    if(fin_scan_resp.getlayer(TCP).flags == 0x14):
        print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Closed ")
elif(fin_scan_resp.haslayer(ICMP)):
    if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
        print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Filtered")
```


- 效果展示：
  - 端口关闭时： 
  ![](./img/tcp-fin-scan-closed.png)
  - 端口开启时：
  ![](./img/tcp-fin-scan-open.png)
  - 端口过滤时：
  ![](./img/tcp-fin-scan-filtered.png)

- 效果分析
  与课本预期相符

- 使用 `nmap` 实现同样功能
  ```bash
  nmap -sF -p 80 -n -vv 172.16.111.132
  ```

  ![](./img/nmap-tcp-fin-scan.png)




**TCP Null Scan**

![](./img/tcp-null-scan.png)

- 代码实现

```py
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "172.16.111.132"
src_port = RandShort()
dst_port = 80

print('TCP null scan:')
print('-----------------------------------------')
null_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=""),timeout=10)
print('-----------------------------------------')

if (str(type(null_scan_resp))=="<class 'NoneType'>"):
    print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Filtered or Open")
elif(null_scan_resp.haslayer(TCP)):
    if(null_scan_resp.getlayer(TCP).flags == 0x14):
        print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Closed ")
elif(null_scan_resp.haslayer(ICMP)):
    if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
        print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Filtered")
```

- 效果展示：
  - 端口关闭时： 
  ![](./img/tcp-null-scan-closed.png)
  - 端口开启时：
  ![](./img/tcp-null-scan-open.png)
  - 端口过滤时：
  ![](./img/tcp-null-scan-filtered.png)

- 效果分析
  与课本预期相符

- 使用 `nmap` 实现同样功能
  ```bash
  nmap -sN -p 80 -n -vv 172.16.111.132
  ```

  ![](./img/nmap-tcp-null-scan.png)





3. UDP scan

![](./img/udp-scan.png)

**在nmap官网查到相关内容，可以依据相关状态进行判断**

![](./img/udp-scan-by-nmap.png)

这里需要开启dns服务，用以开启53端口

![](./img/open-port53.png)

- 代码实现

```py
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "172.16.111.114"
src_port = RandShort()
dst_port = 53
dst_timeout = 1

print('UDP scan:')

def udp_scan(dst_ip,dst_port,dst_timeout):
    print('-----------------------------------------')
    udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout)
    print('-----------------------------------------')
    if (str(type(udp_scan_resp))=="<class 'NoneType'>"):
        retrans = []
        for count in range(0,3):
            retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout))
        for item in retrans:
            if (str(type(item))!="<class 'NoneType'>"):
                udp_scan(dst_ip,dst_port,dst_timeout)
        print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Filtered or Open")
    elif (udp_scan_resp.haslayer(UDP) or udp_scan_resp.getlayer(IP).proto == IP_PROTOS.udp):
        print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Open")
    elif(udp_scan_resp.haslayer(ICMP)):
        if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
            print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Closed")
        elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
            print('State of port '+ str(dst_port) +' on '+ str(dst_ip) +": Filtered")

udp_scan(dst_ip,dst_port,dst_timeout)
```

- 效果展示：
  - 端口关闭时： 
  ![](./img/udp-scan-closed.png)
  - 端口开启时：
  ![](./img/udp-scan-open.png)
  - 端口过滤时：
  ![](./img/udp-scan-filtered.png)

- 效果分析
  与课本预期相符

- 使用 `nmap` 实现同样功能
  ```bash
  nmap -sU -p 53 -n -vv 172.16.111.114
  ```

  ![](img/nmapudp-scan.png)

---


## 出现的问题与解决办法

1. 使用 `python 脚本名` 无法运行
  解决办法： 使用sudo进行提权

2. udp 扫描实验中受害者开启过滤条件，但是脚本和nmap始终无法正确识别。
   解决办法：过滤条件还是有些问题。我设置成了 `iptables -A INPUT -p udp --dport 53 -j REJECT` 将udp协议并且发送到53端口的数据包进行过滤，自然就会过滤掉udp scan ， 从而导致结果错误。需要改成 `iptables -A INPUT -p tcp --dport 53 -j REJECT`

---

## 参考资料

- [Scapy’s documentation](https://scapy.readthedocs.io/en/latest/)
- [浅谈端口扫描技术](https://blog.zeddyu.info/2019/06/12/Scanner/)
- [第五章课件](https://c4pr1c3.github.io/cuc-ns/chap0x05/main.html)
- [如何用Scapy写一个端口扫描器？](https://blog.csdn.net/think_ycx/article/details/50898096)
- [TCP SYN (Stealth) Scan (-sS)](https://nmap.org/book/synscan.html)
- [2019-NS-Public-purplezi](https://github.com/CUCCS/2019-NS-Public-purplezi/blob/ns-0x05/ns-0x05/%E5%9F%BA%E4%BA%8EScapy%E7%BC%96%E5%86%99%E7%AB%AF%E5%8F%A3%E6%89%AB%E6%8F%8F%E5%99%A8.md)

---