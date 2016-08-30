#! /bin/sh

CLUSTER_DNS_SUFFIX=$(sed -ne '/^search / { s/^search [a-zA-Z0-9-]*\.\([^ ]*\) .*$/\1/; p }' </etc/resolv.conf)
export CLUSTER_DNS_SUFFIX

/remap.pl >/usr/local/etc/trafficserver/remap.config

(
	while true; do
		sleep 30

		/remap.pl >/usr/local/etc/trafficserver/remap.config.tmp
		if ! cmp /usr/local/etc/trafficserver/remap.config.tmp /usr/local/etc/trafficserver/remap.config; then
			mv /usr/local/etc/trafficserver/remap.config.tmp /usr/local/etc/trafficserver/remap.config
			/usr/local/bin/traffic_ctl config reload
		fi
	done
) &

exec /usr/local/bin/traffic_cop -o
