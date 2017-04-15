FROM	torchbox/trafficserver:7.0

RUN	set -ex									\
	&& apt-get update							\
	&& apt-get -y install libwww-perl liblwp-protocol-https-perl		\
			libjson-perl						\
	&& rm -rf /var/cache/apt /var/lib/apt/lists/*

COPY	init.sh /
COPY	remap.config records.config plugin.config healthchecks.config header_rewrite.config ip_allow.config /usr/local/etc/trafficserver/

CMD	[ "/init.sh" ]
