sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eno1 -j MASQUERADE
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT


