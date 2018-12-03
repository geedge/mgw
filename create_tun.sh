#!/bin/sh
ip addr add 192.168.30.254/24 dev tap_softether
ip tuntap add dev tun_mgw mode tun
ifconfig tun_mgw up
ip rule add iif tap_softether tab 100
ip route add default dev tun_mgw table 100
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
sysctl -w net.ipv4.conf.default.rp_filter=0
