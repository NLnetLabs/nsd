FROM debian:stable AS builder

RUN apt-get -y update
RUN apt-get -y install build-essential
RUN apt-get -y install autoconf libevent-dev libssl-dev bison flex

ADD . /src
WORKDIR /src

RUN aclocal && autoconf && autoheader
RUN ./configure --with-configdir=/config --localstatedir=/storage
RUN make
RUN make DESTDIR=/tmp/nsd install
RUN tar cvzfC /nsd.tar.gz /tmp/nsd usr/local config


FROM debian:stable

RUN apt-get -y update
RUN apt-get -y install procps ldnsutils openssl libssl1.1 libevent-2.1

COPY --from=builder /nsd.tar.gz /tmp
RUN tar xvzpf /tmp/nsd.tar.gz
RUN rm -f /tmp/nsd.tar.gz

RUN groupadd nsd
RUN useradd -r -m -g nsd nsd

ADD docker/entrypoint.sh /
ADD docker/nsd.conf /config

ENTRYPOINT bash /entrypoint.sh
