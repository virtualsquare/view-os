#!/bin/bash

if [ $# = 0 ] ; then
	echo "Installing to default prefix (/usr/local)"
	PREFIX="/usr/local"
else
	PREFIX=$1
fi

SUBDIRS="ext2 iso9660 encfs"

for i in $SUBDIRS; do
	cd $i
	./configure --prefix=$PREFIX
	make install
	cd ..
done
