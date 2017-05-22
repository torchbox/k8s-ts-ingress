# vim:set sw=8 ts=8 noet:
#
# Copyright (c) 2016-2017 Torchbox Ltd.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

FROM	torchbox/trafficserver:7.0.0-1.0

COPY	. /usr/src/k8s-ts-ingress

RUN	set -ex									\
	&& apt-get update							\
	&& apt-get -y install libssl-dev libjson-c2 libjson-c-dev libc6-dev	\
		make gcc g++ pkgconf						\
	&& cd /usr/src/k8s-ts-ingress						\
	&& ./configure --with-tsxs=/usr/local/bin/tsxs				\
	&& make									\
	&& make test								\
	&& make install								\
	&& apt-get -y remove libjson-c-dev libc6-dev gcc make pkgconf		\
	&& apt-get -y autoremove						\
	&& cd /									\
	&& rm -rf /var/cache/apt /var/lib/apt/lists/* /usr/src/k8s-ts-ingress

COPY	docker/init.sh /
RUN	chmod 755 /init.sh
COPY	docker/remap.config docker/records.config docker/plugin.config		\
	docker/healthchecks.config docker/header_rewrite.config			\
	docker/ip_allow.config							\
	/usr/local/etc/trafficserver/

CMD	[ "/init.sh" ]
