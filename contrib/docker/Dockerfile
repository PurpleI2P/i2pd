FROM alpine:latest
LABEL authors "Mikal Villa <mikal@sigterm.no>, Darknet Villain <supervillain@riseup.net>"

# Expose git branch, tag and URL variables as arguments
ARG GIT_BRANCH="master"
ENV GIT_BRANCH=${GIT_BRANCH}
ARG GIT_TAG=""
ENV GIT_TAG=${GIT_TAG}
ARG REPO_URL="https://github.com/PurpleI2P/i2pd.git"
ENV REPO_URL=${REPO_URL}

ENV I2PD_HOME="/home/i2pd"
ENV DATA_DIR="${I2PD_HOME}/data"

RUN mkdir -p "$I2PD_HOME" "$DATA_DIR" \
    && adduser -S -h "$I2PD_HOME" i2pd \
    && chown -R i2pd:nobody "$I2PD_HOME"

#
# Each RUN is a layer, adding the dependencies and building i2pd in one layer takes around 8-900Mb, so to keep the 
# image under 20mb we need to remove all the build dependencies in the same "RUN" / layer.
#

# 1. install deps, clone and build. 
# 2. strip binaries. 
# 3. Purge all dependencies and other unrelated packages, including build directory. 
RUN apk --no-cache --virtual build-dependendencies add make gcc g++ libtool boost-dev build-base openssl-dev openssl git \
    && mkdir -p /tmp/build \
    && cd /tmp/build && git clone -b ${GIT_BRANCH} ${REPO_URL} \
    && cd i2pd \
    && if [ -n "${GIT_TAG}" ]; then git checkout tags/${GIT_TAG}; fi \
    && make \
    && cp -R contrib/certificates /i2pd_certificates \
    && mkdir -p /usr/local/bin \
    && mv i2pd /usr/local/bin \
    && cd /usr/local/bin \
    && strip i2pd \
    && rm -fr /tmp/build && apk --purge del build-dependendencies build-base fortify-headers boost-dev zlib-dev openssl-dev \
    boost-python3 python3 gdbm boost-unit_test_framework boost-python linux-headers boost-prg_exec_monitor \
    boost-serialization boost-signals boost-wave boost-wserialization boost-math boost-graph boost-regex git pcre \
    libtool g++ gcc pkgconfig

# 2. Adding required libraries to run i2pd to ensure it will run.
RUN apk --no-cache add boost-filesystem boost-system boost-program_options boost-date_time boost-thread boost-iostreams openssl musl-utils libstdc++

COPY entrypoint.sh /entrypoint.sh
RUN chmod a+x /entrypoint.sh

RUN echo "export DATA_DIR=${DATA_DIR}" >> /etc/profile
VOLUME "$DATA_DIR"
EXPOSE 7070 4444 4447 7656 2827 7654 7650
USER i2pd

ENTRYPOINT [ "/entrypoint.sh" ]
