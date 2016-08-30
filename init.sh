#! /bin/sh

CLUSTER_DNS_SUFFIX=$(sed -ne '/^search / { s/^search [a-zA-Z0-9-]*\.\([^ ]*\) .*$/\1/; p }' </etc/resolv.conf)
export CLUSTER_DNS_SUFFIX

/remap.pl >/usr/local/etc/trafficserver/remap.config

exec /usr/local/bin/traffic_cop -o
