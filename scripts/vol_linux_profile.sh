#!/bin/bash
# Create new profile of Linux for use in Volatility
#
VOLHOME=~/volatility
OSNAME="myos"
 cd $VOLHOME/tools/linux && make
 zip /usr/local/lib/python2.7/dist-packages/volatility/plugins/overlays/$OSNAME.zip \
    /boot/System.map-3.13.0-62-generic $VOLHOME/tools/linux/module.dwarf 
