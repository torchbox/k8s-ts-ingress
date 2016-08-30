#! /bin/sh

CLUSTER_DNS_SUFFIX=$(sed -ne '/^search / { s/^search [a-zA-Z0-9-]*\.\([^ ]*\) .*$/\1/; p }' </etc/resolv.conf)
export CLUSTER_DNS_SUFFIX

set -e

mkdir -p /var/lib/trafficserver

# Default to 128MB cache size.
CACHEFILE=/var/lib/trafficserver/cache.db
: ${TS_CACHE_SIZE=128}
if [ \( ! -f $CACHEFILE \) -o $(stat -c%s $CACHEFILE) != $(expr $TS_CACHE_SIZE '*' 1024 '*' 1024) ]; then
	echo 'init.sh: initialising cache file'
	rm -f $CACHEFILE
	dd if=/dev/zero of=$CACHEFILE bs=1M count=128
fi

cat >/usr/local/etc/trafficserver/storage.config <<__EOF__
${CACHEFILE} ${TS_CACHE_SIZE}M
__EOF__

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

# We are running.
touch /run/ts-alive

exec /usr/local/bin/traffic_cop -o
