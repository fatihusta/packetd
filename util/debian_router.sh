#!/bin/sh -x

echo 1 > /proc/sys/net/ipv4/ip_forward

nft add table nat
nft add chain nat prerouting "{ type nat hook prerouting priority -100 ; }"
nft add chain nat postrouting "{ type nat hook postrouting priority 100 ; }"
nft add rule nat postrouting counter masquerade

nft add table ip filter
nft add chain ip filter forward "{ type filter hook forward priority 0 ; }"
nft add chain ip filter input "{ type filter hook input priority 0 ; }"
nft add chain ip filter output "{ type filter hook output priority 0 ; }"
nft add table ip6 filter
nft add chain ip6 filter forward "{ type filter hook forward priority 0 ; }"
nft add chain ip6 filter input "{ type filter hook input priority 0 ; }"
nft add chain ip6 filter output "{ type filter hook output priority 0 ; }"


