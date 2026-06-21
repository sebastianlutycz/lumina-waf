# Dockerfile for LuminaWAF NGINX integration
# Uses Ubuntu to maintain glibc compatibility with the host-built libluminawaf.so
ARG NGINX_VERSION=1.18.0
FROM ubuntu:22.04 AS builder
ARG NGINX_VERSION

RUN apt-get update && apt-get install -y \
    wget build-essential libpcre3-dev zlib1g-dev libssl-dev cmake clang

WORKDIR /build

# Copy the local lumina-waf source. 
COPY . /lumina-waf

# Build libluminawaf.so inside the container
RUN cd /lumina-waf && \
    rm -rf build && mkdir -p build && cd build && \
    cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ .. && \
    make luminawaf -j4

# Download NGINX source for module compilation
RUN wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxf nginx-${NGINX_VERSION}.tar.gz && \
    cd nginx-${NGINX_VERSION} && \
    ./configure --with-compat --add-dynamic-module=/lumina-waf/nginx_module && \
    make modules

FROM ubuntu:22.04
ARG NGINX_VERSION

RUN apt-get update && apt-get install -y nginx libpcre3 && rm -rf /var/lib/apt/lists/*

# Copy the NGINX dynamic module
COPY --from=builder /build/nginx-${NGINX_VERSION}/objs/ngx_http_luminawaf_module.so /usr/share/nginx/modules/

# Copy the container-built shared library
COPY --from=builder /lumina-waf/build/libluminawaf.so /usr/lib/

# Inject module load directive
RUN sed -i '1i load_module /usr/share/nginx/modules/ngx_http_luminawaf_module.so;' /etc/nginx/nginx.conf

# Expose port
EXPOSE 80

STOPSIGNAL SIGQUIT
CMD ["nginx", "-g", "daemon off;"]
