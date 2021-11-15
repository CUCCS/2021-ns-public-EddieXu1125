#!/bin/bash

IPT="/sbin/iptables"

# 删除表中所有规则
$IPT --flush
# 删除所有规则链
$IPT --delete-chain

# 定义默认策略
# 其中 INPUT链默认为DROP（丢弃），FORWARD链默认为DROP（丢弃），OUTPUT链默认为ACCEPt(接受)
$IPT -P INPUT DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT ACCEPT

# 创建新的用户自定义规则链forward_demo、icmp_demo
$IPT -N forward_demo
$IPT -N icmp_demo

# 在规则列表最后增加规则
# 接受本地回环网卡的输入与输出
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# 对INPUT链执行过滤操作
# All TCP sessions should begin with SYN
# 丢弃所有新建立的并且没有设置syn标志位的tcp连接
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -s 0.0.0.0/0 -j DROP
# 接受所有状态为ESTABLISHED,RELATED的连接
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 对输入的所有使用icmp协议的数据包执行icmp_demo链中的过滤规则
$IPT -A INPUT -p icmp -j icmp_demo

# 向icmp_demo链追加规则，eth0接受使用icmp协议的数据包
$IPT -A icmp_demo -p icmp -i eth0 -j ACCEPT
# 防火墙将停止为数据包执行icmp_demo链中的下一组规则。控制将返回到调用链。
$IPT -A icmp_demo -j RETURN

# 对FORWARD链添加forward_demo链中的规则
$IPT -A FORWARD -j forward_demo

# 以下是在forward_demo链中追加规则
# 当数据包匹配上forward_demo链的规则，在日志中的log有特定前缀：FORWARD_DEMO
$IPT -A forward_demo -j LOG --log-prefix FORWARD_DEMO
# 丢弃掉使用tcp连接访问80端口并且使用bm方法匹配到'baidu'字符串的数据包（简单来说：http数据包中不能出现baidu这个字符串）
$IPT -A forward_demo -p tcp --dport 80 -m string --algo bm --string 'baidu' -j LOG --log-prefix VISIT_BAIDU 
# 接受使用tcp协议的并且ip来自于172.16.18.11这一ip地址的数据包
$IPT -A forward_demo -p tcp -s 172.16.18.11 -j ACCEPT
# 接受使用tcp协议的并且ip要去往172.16.18.11这一ip地址的数据包
$IPT -A forward_demo -p tcp -d 172.16.18.11 -j ACCEPT
# 接受172.16.18.11的udp探测（允许172.16.18.11进行dns解析）
$IPT -A forward_demo -p udp -s 172.16.18.11 --dport 53 -j ACCEPT
# 允许172.16.18.1进行dns解析
$IPT -A forward_demo -p udp -s 172.16.18.1  --dport 53 -j ACCEPT
# 允许192.168.1.1进行dns解析
$IPT -A forward_demo -p udp -s 192.168.1.1  --sport 53 -j ACCEPT
# 允许172.16.18.1进行tcp连接
$IPT -A forward_demo -p tcp -s 172.16.18.1 -j ACCEPT
# 防火墙将停止为IP地址为172.16.18.1的数据包执行icmp_demo链中的下一组规则。控制将返回到调用链。
$IPT -A forward_demo -s 172.16.18.1 -j RETURN


# 指定nat表中的POSTROUTING链，添加规则
# 对于源地址为172.16.18.1/24，输出网络接口为eth0的数据包进行ip伪装
$IPT -t nat -A POSTROUTING -s 172.16.18.0/24 -o eth0 -j MASQUERADE

