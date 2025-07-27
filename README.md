# Purpose
This project is about my personal home network setup in China mainland, it including the OpenVPN Fanqiang solution, the DNSMASQ+dnscrypt-proxy based DNS solution, Policy based routing and dynamic best route detection (under construction)

## System Overview
https://drive.google.com/file/d/1FD7U2696IMrDkZZQ3uyJyUzsixar7rqv/view?usp=sharing

## Pre-requisites
Prepare below:
1. A virtual machine out of China for running OpenVPN, you can purchase services from bandwagonhost.com.

2. China intranet access
You need to contact ISP like China mobile, China telecom for let you access China intranet, and you can access baidu.com, taobao.com, etc.

3. Two Ubuntu based computers 
You need 2 Ubuntu based computers, it could be old laptops, Raspberry pi or Jetson devices. one of them is the home router, another is for detecting the best route.
You need to install Ubuntu 18 or newer version on the computers, Python is mandatory.

4. A USB to RJ45 network adapter
In the case your computer has only one network adapter, you need to purchase an USB to RJ45 adapter for your router. it needs 2 network adapters.

5. A home WIFI router
To provide internet access to your iPhone, iPad and Android based mobile phones.

6. A 1000M switch
To provide wired connection to your computers at home.


## Steps
1. Setup and test OpenVPN
Check vpn/README.md

2. Setup and test DNS
Check dns/README.md

3. Setup Policy Based Routing (PBR)
Check pbr/README.md

4. Setup Dynamic Routing (DR)
Check dr/README.md



