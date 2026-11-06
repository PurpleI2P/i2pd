#!/bin/sh
COMMAND=/usr/local/bin/i2pd
# To make ports exposeable
# Note: $DATA_DIR is defined in /etc/profile

if [ "$1" = "--help" ]; then
    set -- $COMMAND --help
else
    # Only create the symlink if no certificates path exists yet (file,
    # directory, or symlink, including a stale one). Re-running ln -s on
    # restart would follow the existing symlink and try to create a link
    # inside the (read-only) image-layer target, which fails with
    # Permission denied / Read-only file system (issue #1996).
    [ -e "$DATA_DIR"/certificates ] || [ -L "$DATA_DIR"/certificates ] || ln -s /i2pd_certificates "$DATA_DIR"/certificates
    set -- $COMMAND $DEFAULT_ARGS $@
fi

exec "$@"
