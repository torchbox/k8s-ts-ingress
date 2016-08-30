FROM	torchbox/trafficserver:7.0

RUN	apt-get update && apt-get -y install libwww-perl liblwp-protocol-https-perl libjson-perl

COPY	init.sh /
COPY	remap.pl /
COPY	records.config /usr/local/etc/trafficserver

CMD	[ "/init.sh" ]
