#! /bin/bash

MY_OVS_BUILD_ROOT=`pwd`
export DPDK_DIR="$MY_OVS_BUILD_ROOT/../anlaneg_dpdk"
export DPDK_TARGET='x86_64-native-linuxapp-gcc'
export OVS_DIR="$MY_OVS_BUILD_ROOT"
export DPDK_BUILD="$DPDK_DIR/$DPDK_TARGET"
#function compile_dpdk()
#{
#    (echo "compile dpdk";cd $DPDK_DIR;make EXTRA_CFLAGS="-O0 -g" install T=$DPDK_TARGET DESTDIR=install);
#}

function compile_ovs()
{
    #apt-get install automake libtool libnuma-dev libpcap-dev
    (echo 'compile ovs';cd $OVS_DIR;./boot.sh;./configure --with-dpdk=$DPDK_BUILD --with-debug  CFLAGS='-g' ; make -j4 1>/dev/null);
}

compile_ovs

