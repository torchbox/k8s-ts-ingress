
TSDIR?=		/usr/local/trafficserver
CGO_CPPFLAGS?=	-I${TSDIR}/include

REMAP_SRC=	remap.go			\
		remap_controller.go

SSL_SRC=	ssl.go ssl_plugin.go

default: kubernetes_remap.so kubernetes_ssl.so

kubernetes_remap.so: ${REMAP_SRC}
	CGO_CPPFLAGS="${CGO_CPPFLAGS}" go build -o kubernetes_remap.so -buildmode=c-shared ${REMAP_SRC}

kubernetes_ssl.so: ${SSL_SRC}
	CGO_CPPFLAGS="${CGO_CPPFLAGS}" go build -o kubernetes_ssl.so -buildmode=c-shared ${SSL_SRC}

build:
	#docker build --pull -t torchbox/trafficserver-ingress-controller:latest .

push:
	docker push torchbox/trafficserver-ingress-controller:latest
