#! /bin/sh
# vim:set sw=8 ts=8 noet:
#
# This is a trivial HTTP server for use in tests.  It only supports GET requests
# and makes no attempt to validate its input or conform to any HTTP
# specification.

# Travis-CI won't let us remove netcat-openbsd, so instead check for the
# normal version explicitly.
NETCAT=nc
if [ -e /bin/nc.traditional ]; then
	NETCAT=/bin/nc.traditional
fi

if [ -z "$1" ]; then
	echo >&2 "usage: $0 <handle|address>"
	exit 1
fi

port=48080
[ ! -z "$2" ] && port=$2

ncpid=0

if [ "$1" = "handle" ]; then
	hasims=no
	read method path version

	while :; do
		read line
		if echo "$line" | grep -qi "If-Modified-Since:"; then
			hasims=yes
		fi

		if echo "$line" | grep -q '^[[:space:]]*$'; then
			break
		fi
	done

	printf >&2 'handling request.\n'

	if (echo "$path" | grep -q "/notmodified/") && [ $hasims = yes ]; then
		printf 'HTTP/1.0 304 Not modified\r\n'
		printf 'Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\n'
		printf 'Connection: close\r\n'
		printf '\r\n\r\n'
		exit 0
	fi

	printf 'HTTP/1.0 200 OK\r\n'
	printf 'Connection: close\r\n'
	printf 'Content-Type: text/plain;charset=UTF-8\r\n'

	# Set various headers based on the request path.  These are cumulative,
	# so a request path might be /cached/serverpush/nexthopcc/foobar.

	if echo "$path" | grep -q "/cached/"; then
		printf 'Cache-Control: public, max-age=3600\r\n'
	fi
	if echo "$path" | grep -q "/server-push/"; then
		printf 'Link: </cached/foo>; rel=preload; as=script\r\n'
		printf 'Link: </cached/bar>; rel=preload; as=script\r\n'
	fi
	if echo "$path" | grep -q "/nexthopcc/"; then
		printf 'Cache-Control: public, max-age=7200\r\n'
		printf 'X-Next-Hop-Cache-Control: no-cache, max-age=3600, public\r\n'
	fi
	if echo "$path" | grep -q "/setcookie/"; then
		printf 'Set-Cookie: mycookie=foobar\r\n'
	fi
	printf '\r\n'
	printf 'Request method: %s\n' "$method"
	printf 'Request path: %s\n' "$path"
	exit 0
fi

trap '[ $ncpid != 0 ] && kill $ncpid; exit 0' INT TERM EXIT 0

while :; do
	$NETCAT -l -p $port -c "$0 handle" "$1" & ncpid=$!
	wait $ncpid
	ncpid=0
done
