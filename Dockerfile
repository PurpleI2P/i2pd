FROM alpine:latest as builder

# We will build docker image in 2 stages.
# This is 1st stage and we will use it to build i2pd executable.

# 1. install deps
RUN apk add --no-cache build-base libtool boost-dev openssl-dev zlib-dev

# 2. copy sources
WORKDIR /src
COPY . /src

# 3. build
RUN make -j$(nproc)
# 4. strip executable
RUN strip --strip-all i2pd

FROM alpine:latest

# This is 2nd stage and it will be used to run i2pd.

# 1. create user to run i2pd from it
RUN mkdir /var/lib/i2pd && adduser -S -h /var/lib/i2pd i2pd \
    && chown -R i2pd:nobody /var/lib/i2pd

# 2. install required libraries to run i2pd
RUN apk add --no-cache boost-system boost-date_time boost-filesystem \
    boost-program_options libstdc++ libgcc openssl zlib su-exec

# 3. copy i2pd binary from 1st stage
COPY --from=builder /src/i2pd /usr/local/bin/

# 4. copy entrypoint.sh
COPY build/docker/entrypoint.sh /entrypoint.sh
RUN chmod a+x /entrypoint.sh

VOLUME [ "/var/lib/i2pd" ]

EXPOSE 7070 4444 4447 7656 2827 7654 7650

ENTRYPOINT [ "/entrypoint.sh" ]
