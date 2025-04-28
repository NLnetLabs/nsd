#!/bin/sh
# kFreeBSD do not accept scripts as interpreters, using #!/bin/sh and sourcing.
if [ true != "$INIT_D_SCRIPT_SOURCED" ] ; then
    set "$0" "$@"; INIT_D_SCRIPT_SOURCED=true . /lib/init/init-d-script
fi
### BEGIN INIT INFO
# Provides:          nsd
# Required-Start:    $network $local_fs $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: authoritative domain name server
# Description:       NSD is a authoritative-only domain name server
### END INIT INFO

NAME=nsd                  # Introduce the short server's name here
DAEMON=/usr/sbin/$NAME    # Introduce the server's location here
DESC="Name Server Daemon" # Introduce a short description here
PIDFILE=$(nsd-checkconf -o pidfile /etc/nsd/nsd.conf)

do_tmpfiles() {
    local type path mode user group

    if [ -r "/usr/lib/tmpfiles.d/$1.conf" ]; then
        TMPFILE=/usr/lib/tmpfiles.d/$1.conf
    fi
    if [ -r "/etc/tmpfiles.d/$1.conf" ]; then
        TMPFILE=/etc/tmpfiles.d/$1.conf
    fi

    while read type path mode user group age argument; do
        if [ "$type" = "d" ]; then
            mkdir -p "$path"
            chmod "$mode" "$path"
            chown "$user:$group" "$path"
        fi
    done < "$TMPFILE"
}

do_start_prepare() {
    do_tmpfiles $(basename $0)
}

do_reload() {
    nsd-control reload >/dev/null
    return $?
}
