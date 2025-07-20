sudo /usr/sbin/iptables -t nat -F
sudo /usr/sbin/iptables -t nat -X

sudo /usr/sbin/iptables -t nat -A POSTROUTING -o eno1 -j MASQUERADE
sudo ip route add 192.168.1.0/24 via 192.168.2.2

