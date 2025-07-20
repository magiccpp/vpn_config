#!/usr/bin/bash
echo "Script started at $(date)" >> /tmp/crontab_19_log.txt
allow_source_ip() {
  echo $1 | awk '{printf("sudo /usr/sbin/iptables -t nat -I POSTROUTING  -s %s -o eno1 -j MASQUERADE\n", $1)}'|sh
}



echo "stop gateway"
sudo /usr/sbin/iptables -t nat -F
sudo /usr/sbin/iptables -t nat -X
echo "gateway stopped"
#allow_source_ip 192.168.1.37
#Anna:
#allow_source_ip 192.168.1.38

# Xinnan IPAD:
#allow_source_ip 192.168.1.59
allow_source_ip 192.168.1.33
allow_source_ip 192.168.1.39
allow_source_ip 192.168.1.51
allow_source_ip 192.168.1.61
allow_source_ip 192.168.1.60
#allow_source_ip 192.168.1.47
allow_source_ip 192.168.1.46
allow_source_ip 192.168.1.40
allow_source_ip 192.168.1.42
allow_source_ip 192.168.1.41
#allow_source_ip 192.168.1.42
#allow_source_ip 192.168.1.42

# Big ipad
#allow_source_ip 192.168.1.44
#allow_source_ip 192.168.1.53
allow_source_ip 192.168.2.0/24
allow_source_ip 10.8.0.0/24
