FROM alpine:latest
USER root
RUN export http_proxy=http://proxy.rd.francetelecom.fr:8080/  \
&& export https_proxy=http://proxy.rd.francetelecom.fr:8080/ \
&& apk add curl \
&& apk add wget \
&& apk add make \
&& apk add perl \
&& apk add --no-cache linux-headers \
&& apk --no-cache --update add build-base \
&& wget https://www.openssl.org/source/openssl-3.1.0.tar.gz \
&& tar -xvf openssl-3.1.0.tar.gz \
&& cd openssl-3.1.0 \
&& ./Configure enable-ktls \
&& make -j10 \
&& make install
