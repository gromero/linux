#!/bin/bash

if [[ -z "$TRAVIS_BUILD_DIR" || -z "$TARGET" || -z "$IMAGE" || -z "$SUBARCH" ]]; then
    echo "Error: required environment variables not set!"
    exit 1
fi

cmd="docker run --rm "
cmd+="--network none "
cmd+="-w /linux "
cmd+="-v $TRAVIS_BUILD_DIR:/linux:ro "

cmd+="-e ARCH "
cmd+="-e DEFCONFIG=$DEFCONFIG "
cmd+="-e JFACTOR=$(nproc) "
cmd+="-e KBUILD_BUILD_TIMESTAMP=$(date +%Y-%m-%d) "

if [[ "$SUBARCH" == "ppc64" ]]; then
    cross="powerpc-linux-gnu-"
else
    cross="powerpc64le-linux-gnu-"
fi
cmd+="-e CROSS_COMPILE=$cross "

mkdir -p $HOME/output
cmd+="-v $HOME/output:/output:rw "

cmd+="-v $HOME/.ccache:/ccache:rw "
cmd+="-e CCACHE_DIR=/ccache "
cmd+="-e CCACHE=1 "

cmd+="linuxppc/build:$IMAGE-$(uname -m) "
cmd+="/bin/container-build.sh $TARGET"

(set -x; $cmd)

exit $?
