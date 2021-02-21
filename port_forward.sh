#!/usr/bin/env sh

sysctl -w net.ipv4.conf.ens4.route_localnet=1
iptables -t nat -I PREROUTING -p tcp --dport 80 -j DNAT --to-destination 127.0.0.1:8080
