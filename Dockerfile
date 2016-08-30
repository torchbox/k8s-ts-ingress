FROM	torchbox/trafficserver:7.0

RUN	apt-get update && apt-get -y install libwww-perl liblwp-protocol-https-perl libjson-perl

COPY	init.sh /
COPY	remap.pl /
COPY	records.config /usr/local/etc/trafficserver
COPY	plugin.config /usr/local/etc/trafficserver
COPY	healthchecks.config /usr/local/etc/trafficserver
COPY	header_rewrite.config /usr/local/etc/trafficserver

CMD	[ "/init.sh" ]
