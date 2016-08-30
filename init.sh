#! /bin/sh

/remap.pl >/usr/local/etc/trafficserver/remap.config

exec /usr/local/bin/traffic_cop -o
