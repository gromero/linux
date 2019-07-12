#!/bin/bash

export ARCH
export CROSS_COMPILE

gcc_version=$(${CROSS_COMPILE}gcc --version | head -1)
ld_version=$(${CROSS_COMPILE}ld --version | head -1)

echo "## ARCH          = $ARCH"
echo "## CROSS_COMPILE = $CROSS_COMPILE"
echo "## VERSION (gcc) = $gcc_version"
echo "## VERSION (ld)  = $ld_version"
echo "## TIMESTAMP     = $KBUILD_BUILD_TIMESTAMP"

nproc=$(nproc)

if [[ -n "$SELFTESTS" ]]; then
    (set -x; make -j $nproc -C tools/testing/selftests TARGETS=powerpc)
    rc=$?
    if [[ $rc -eq 0 ]]; then
	(set -x; make -j $nproc -C tools/testing/selftests)
	rc=$?
    fi
else
    echo "## DEFCONFIG     = $DEFCONFIG"
    (set -x; make -s $DEFCONFIG)
    rc=$?

    if [[ $rc -eq 0 ]]; then
         (set -x; make -s -j $nproc)
         rc=$?
    fi
fi

if [[ $rc -ne 0 ]]; then
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!! Error build failed rc $rc"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
else
    echo "## Build completed OK"
fi

exit $rc
