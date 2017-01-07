#!/bin/sh

ARGS=""
if [ "${ENABLE_IPV6}" != "" ]; then
  ARGS="${ARGS} –ipv6"
fi

if [ "${LOGLEVEL}" != "" ]; then
  ARGS="${ARGS} –loglevel=${LOGLEVEL}"
fi

if [ "${ENABLE_AUTH}" != "" ]; then
  ARGS="${ARGS} –http.auth"
fi


# To make ports exposeable
DEFAULT_ARGS=" –http.address=0.0.0.0 –httpproxy.address=0.0.0.0 -socksproxy.address=0.0.0.0 –sam.address=0.0.0.0 –bob.address=0.0.0.0 –i2cp.address=0.0.0.0 –i2pcontrol.port=0.0.0.0 –upnp.enabled=false -service "

mkdir -p /var/lib/i2pd && chown -R i2pd:nobody /var/lib/i2pd && chmod u+rw /var/lib/i2pd

gosu i2pd i2pd $DEFAULT_ARGS $ARGS


