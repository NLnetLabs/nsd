#!/bin/sh

# Build a NSD distribution tar from the CVS repository.

# Abort script on unexpected errors.
set -e

# Remember the current working directory.
cwd=`pwd`

# Utility functions.
usage () {
    cat >&2 <<EOF
Usage $0: [-h] [-s] [-d CVS_root] [-r revision]
Generate a distribution tar file for NSD.

    -h           This usage information.
    -s           Build a snapshot distribution file.  The current date is
                 automatically appended to the current NSD version number.
    -d CVS_root  Retrieve the NSD source from the specified repository.
                 If this option is not specified the current value of the
                 CVSROOT environment variable is used.
    -r revision  Specify the NSD revision to retrieve.  If not specified
                 the HEAD revision is retrieved.
EOF
    exit 1
}

info () {
    echo "$0: info: $1"
}

error () {
    echo "$0: error: $1" >&2
    exit 1
}

question () {
    printf "%s (y/n) " "$*"
    read answer
    case "$answer" in
        [Yy]|[Yy][Ee][Ss])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Only use cleanup and error_cleanup after generating the temporary
# working directory.
cleanup () {
    info "Deleting temporary working directory."
    cd $cwd && rm -rf $temp_dir
}

error_cleanup () {
    echo "$0: error: $1" >&2
    cleanup
    exit 1
}

replace_version () {
    info "Updating '$1' with the version number."
    (cp "$1" "$1".orig && \
        sed -e "s/@version@/$version/g" < "$1".orig > "$1" && \
        rm "$1".orig) || error_cleanup "Version replacement for $1 failed."
}

REVISION="HEAD"
SNAPSHOT="no"

# Parse the command line arguments.
while [ "$1" ]; do
    case "$1" in
        "-h")
            usage
            ;;
        "-d")
            CVSROOT="$2"
            shift
            ;;
        "-r")
            REVISION="$2"
            shift
            ;;
        "-s")
            SNAPSHOT="yes"
            ;;
        *)
            error "Unrecognized argument -- $1"
            ;;
    esac
    shift
done

# Check if CVSROOT is specified.
if [ -z "$CVSROOT" ]; then
    error "CVSROOT must be specified (using -d)"
fi

# Check if the NSD CVS revision is specified.
if [ -z "$REVISION" ]; then
    error "REVISION must be specified (using -r)"
fi

# Start the packaging process.
info "CVSROOT  is $CVSROOT"
info "REVISION is $REVISION"
info "SNAPSHOT is $SNAPSHOT"

question "Do you wish to continue with these settings?" || error "User abort."


# Creating temp directory
info "Creating temporary working directory"
temp_dir=`mktemp -d nsd-dist-XXXXXX`
info "Directory '$temp_dir' created."
cd $temp_dir

info "Exporting source from CVS."
cvs -d "$CVSROOT" -Q export -r "$REVISION" nsd || error_cleanup "CVS command failed"

cd nsd || error_cleanup "NSD not exported correctly from CVS"

info "Building configure script (autoconf)."
autoconf || error_cleanup "Autoconf failed."

info "Building config.h.in (autoheader)."
autoheader || error_cleanup "Autoheader failed."

rm -r autom4te* || error_cleanup "Failed to remove autoconf cache directory."

rm .c-mode-rc.el || error_cleanup "Failed to remove .c-mode-rc.el."
rm makedist.sh || error_cleanup "Failed to remove makedist.sh."

info "Determining NSD version."
version=`./configure --version | head -1 | awk '{ print $3 }'` || \
    error_cleanup "Cannot determine version number."

info "NSD version: $version"

if [ "$SNAPSHOT" = "yes" ]; then
    info "Building NSD snapshot."
    version="$version-`date +%Y%m%d`"
    info "Snapshot version number: $version"
fi

replace_version README
replace_version nsd.8
replace_version nsdc.8
replace_version zonec.8

info "Renaming NSD directory to nsd-$version."
cd ..
mv nsd nsd-$version || error_cleanup "Failed to rename NSD directory."

tarfile="../nsd-$version.tar.gz"

if [ -f $tarfile ]; then
    (question "The file $tarfile already exists.  Overwrite?" \
        && rm -f $tarfile) || error_cleanup "User abort."
fi

info "Creating tar nsd-$version.tar.gz"
tar czf ../nsd-$version.tar.gz nsd-$version || error_cleanup "Failed to create tar file."

cleanup

info "NSD distribution created successfully."
