FROM debian:stable-slim

ENV BUILD_PKGS \
    build-essential \
    autoconf \
    libevent-dev \
    libssl-dev \
    bison \
    flex

# Install dependencies
RUN apt-get update && \
    apt-get install -yqq ${BUILD_PKGS}

# Build the project
COPY . /nsd-src
WORKDIR /nsd-src
RUN aclocal && \
    autoconf && \
    autoheader && \
    ./configure --with-configdir=/config --localstatedir=/storage && \
    make && \
    make DESTDIR=/tmp/nsd-install install

# Save result
RUN tar cvzfC /nsd.tar.gz /tmp/nsd-install usr/local config storage


FROM debian:stable-slim

# Environment
ENV RUNTIME_PKGS \
    procps \
    ldnsutils \
    openssl \
    libssl1.1 \
    libevent-2.1

# Copy artifacts
COPY --from=0 /nsd.tar.gz /tmp
RUN tar xvzpf /tmp/nsd.tar.gz
RUN rm -f /tmp/nsd.tar.gz

# Install dependencies and create nsd user and group
ARG UID=53
RUN apt-get update && \
    apt-get install -yqq ${RUNTIME_PKGS} && \
    rm -rf /var/lib/apt/lists/* && \
    ldconfig && \
    adduser --quiet --system --group --no-create-home --home /storage --uid=${UID} nsd && \
    install -d -o nsd -g nsd /config /storage && \
    chown -R nsd:nsd /config /storage

# Add default config
ADD docker/nsd.conf /config

# Add entrypoint
ADD docker/entrypoint.sh /
ENTRYPOINT bash /entrypoint.sh

# Expose port
EXPOSE 53/UDP
EXPOSE 53/TCP

# Prepare shared directories
VOLUME /config
VOLUME /storage
