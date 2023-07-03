FROM debian:bookworm-slim

ENV NGINX_VERSION   1.23.2
ENV PKG_RELEASE     1~bookworm

RUN set -x \
    && echo "deb-src http://deb.debian.org/debian bookworm main" >> /etc/apt/sources.list \
    && echo "deb-src http://deb.debian.org/debian-security bookworm-security main" >> /etc/apt/sources.list \
    && echo "deb-src http://deb.debian.org/debian bookworm-updates main" >> /etc/apt/sources.list \
    && cat /etc/apt/sources.list \
    && cd /etc/apt/apt.conf.d \
    && export http_proxy=http://proxy.rd.francetelecom.fr:8080/  \
    && export https_proxy=http://proxy.rd.francetelecom.fr:8080/ \
    && apt-get update \
    && apt-get -y  install curl \
    && apt-get -y install gedit \
    && apt-get -y install nano \
    && apt-get install --no-install-recommends --no-install-suggests -y gnupg1 ca-certificates wget \
    && apt-get build-dep nginx -y \
    && dpkgArch="$(dpkg --print-architecture)" \
    && apt-get remove --purge --auto-remove -y \
    && rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx.list

RUN set -x \
    && export http_proxy=http://proxy.rd.francetelecom.fr:8080/  \
    && export https_proxy=http://proxy.rd.francetelecom.fr:8080/ \
    && mkdir -p /var/cache/nginx \
    && wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && wget https://www.openssl.org/source/openssl-3.0.0.tar.gz \
    && tar zxf openssl-3.0.0.tar.gz \
    && tar zxf nginx-${NGINX_VERSION}.tar.gz \
    && cd nginx-${NGINX_VERSION} \
    && ./configure \
    --with-debug \
    --prefix=/usr \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --with-compat \
    --with-file-aio \
    --with-threads \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_mp4_module \
    --with-http_random_index_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_slice_module \
    --with-http_ssl_module \
    --with-http_stub_status_module \
    --with-http_sub_module \
    --with-http_v2_module \
    --with-mail \
    --with-mail_ssl_module \
    --with-stream \
    --with-stream_realip_module \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-openssl=../openssl-3.0.0 \
    --with-openssl-opt=enable-ktls \
    --with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' \
    --with-ld-opt='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie' \
    && make -j4 \
    && make install \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log \
    && mkdir /docker-entrypoint.d

COPY docker-entrypoint.sh /
COPY 10-listen-on-ipv6-by-default.sh /docker-entrypoint.d
COPY 20-envsubst-on-templates.sh /docker-entrypoint.d
COPY 30-tune-worker-processes.sh /docker-entrypoint.d
ENTRYPOINT ["/docker-entrypoint.sh"]

EXPOSE 443
EXPOSE 80

STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "daemon off;"]
