# vpn_config
the VPN configurations for breaking FW

## LINUX PBR STEPS
Make a IP rule file like below:
```
create bypass_vpn hash:net family inet hashsize 2048 maxelem 65536
add bypass_vpn 1.0.1.0/24
add bypass_vpn 1.0.2.0/23
add bypass_vpn 1.0.8.0/21
add bypass_vpn 1.0.32.0/19
```

Then 
```
sudo ipset restore < bypass_vpn_rules.ipset
# OUTPUT for locally originated packets
sudo iptables -t mangle -A OUTPUT -m set --match-set bypass_vpn dst -j MARK --set-mark 100
# PREROUTE for packets originated from other computers
sudo iptables -t mangle -A PREROUTING -m set --match-set bypass_vpn dst -j MARK --set-mark 100
```

Edit the route table
```
sudo nano /etc/iproute2/rt_tables
```
add below:
```
200 bypass_vpn
```

Add Routes to the Custom Table

sudo ip route add default via 192.168.71.1 table bypass_vpn
sudo ip rule add fwmark 100 table bypass_vpn

 Persisting ipset
```
sudo apt-get install ipset-persistent
sudo ipset save bypass_vpn -f /etc/ipset/bypass_vpn.conf
```

## To add new IP into the PBR
use tcpdump to monitor the IPs go to VPN:
```
sudo tcpdump tcp -i tun0 -n -q -t -l
```

then access the domestic website, if there is traffic goes to VPN, then you can write down the IP address, add it into the ipset.
