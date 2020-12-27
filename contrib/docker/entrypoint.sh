#!/bin/sh
COMMAND=/usr/local/bin/i2pd
# To make ports exposeable
# Note: $DATA_DIR is defined in /etc/profile

if [ "$1" = "--help" ]; then
    set -- $COMMAND --help
else
    ln -s /i2pd_certificates "$DATA_DIR"/certificates
    set -- $COMMAND $DEFAULT_ARGS $@
fi

exec "$@"
