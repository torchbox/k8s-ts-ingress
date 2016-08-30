#! /bin/sh

/remap.pl >/usr/local/etc/trafficserver/remap.config
CLUSTER_DNS_SUFFIX=$(sed -ne '/^search / { s/^search [a-zA-Z0-9-]*\.\([^ ]*\) .*$/\1/; p }' </etc/resolv.conf)
export CLUSTER_DNS_SUFFIX

exec /usr/local/bin/traffic_cop -o
