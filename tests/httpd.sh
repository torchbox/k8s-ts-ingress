#! /bin/sh
# vim:set sw=8 ts=8 noet:
#
# This is a trivial HTTP server for use in tests.  It only supports GET requests
# and makes no attempt to validate its input or conform to any HTTP
# specification.

set -x 

if [ -z "$1" ]; then
	echo >&2 "usage: $0 <handle|address>"
	exit 1
fi

ncpid=0

if [ "$1" = "handle" ]; then
	read method path version

	while :; do
		read line
		if echo "$line" | grep -q '^[[:space:]]*$'; then
			break
		fi
	done

	printf 'HTTP/1.0 200 OK\r\n'
	printf 'Connection: close\r\n'
	printf 'Content-Type: text/plain;charset=UTF-8\r\n'
	printf '\r\n'
	printf 'Request method: %s\n' "$method"
	printf 'Request path: %s\n' "$path"
	exit 0
fi

trap '[ $ncpid != 0 ] && kill $ncpid; exit 0' INT TERM EXIT 0

while :; do
	nc -l -p 48080 -c "$0 handle" "$1" & ncpid=$!
	wait $ncpid
	ncpid=0
done
