FROM alpine:latest

MAINTAINER Mikal Villa <mikal@sigterm.no>

ENV GIT_BRANCH="master"
ENV I2PD_PREFIX="/opt/i2pd-${GIT_BRANCH}"
ENV PATH=${I2PD_PREFIX}/bin:$PATH

ENV GOSU_VERSION=1.7
ENV GOSU_SHASUM="34049cfc713e8b74b90d6de49690fa601dc040021980812b2f1f691534be8a50  /usr/local/bin/gosu"

RUN mkdir /user && adduser -S -h /user i2pd && chown -R i2pd:nobody /user


#
# Each RUN is a layer, adding the dependencies and building i2pd in one layer takes around 8-900Mb, so to keep the 
# image under 20mb we need to remove all the build dependencies in the same "RUN" / layer.
#

# 1. install deps, clone and build. 
# 2. strip binaries. 
# 3. Purge all dependencies and other unrelated packages, including build directory. 
RUN apk --no-cache --virtual build-dependendencies add make gcc g++ libtool boost-dev build-base openssl-dev openssl git \
    && mkdir -p /tmp/build \
    && cd /tmp/build && git clone -b ${GIT_BRANCH} https://github.com/PurpleI2P/i2pd.git \
    && cd i2pd \
    && make -j4 \
    && mkdir -p ${I2PD_PREFIX}/bin \
    && mv i2pd ${I2PD_PREFIX}/bin/ \
    && cd ${I2PD_PREFIX}/bin \
    && strip i2pd \
    && rm -fr /tmp/build && apk --purge del build-dependendencies build-base fortify-headers boost-dev zlib-dev openssl-dev \
    boost-python3 python3 gdbm boost-unit_test_framework boost-python linux-headers boost-prg_exec_monitor \
    boost-serialization boost-signals boost-wave boost-wserialization boost-math boost-graph boost-regex git pcre \
    libtool g++ gcc pkgconfig

# 2. Adding required libraries to run i2pd to ensure it will run.
RUN apk --no-cache add boost-filesystem boost-system boost-program_options boost-date_time boost-thread boost-iostreams openssl musl-utils libstdc++

# Gosu is a replacement for su/sudo in docker and not a backdoor :) See https://github.com/tianon/gosu
RUN wget -O /usr/local/bin/gosu https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-amd64 \
    && echo "${GOSU_SHASUM}" | sha256sum -c && chmod +x /usr/local/bin/gosu

COPY entrypoint.sh /entrypoint.sh

RUN chmod a+x /entrypoint.sh
RUN echo "export PATH=${PATH}" >> /etc/profile

VOLUME [ "/var/lib/i2pd" ]

EXPOSE 7070 4444 4447 7656 2827 7654 7650

ENTRYPOINT [ "/entrypoint.sh" ]

