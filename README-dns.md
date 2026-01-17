dnsmasq: /etc/dnsmasq.q/chn_domains_ken.txt 

the last line is: server=127.0.0.1#5454
in /etc/dnsmasq.conf, you must include the tun0 IP, like 10.8.0.10, into the listen_addresses list: i.e. listen-address=192.168.4.1,10.8.0.10


dnscrypt-proxy:
/etc/dnscrypt-proxy/dnscrypt-proxy.toml

8.8.8.8 is configured there.

