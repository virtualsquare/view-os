rm -rf .umfuse/
mkdir -p .umfuse
g++ -DHAVE_CONFIG -I. -I.. -I../intl -DUMFUSE -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=25 -D__STDC_FORMAT_MACROS -DRLOG_COMPONENT=encfs -DLOCALEDIR=\"/usr/local/share/locale\" -W -Wall -Wshadow -Wpointer-arith -g -c *.cpp
rm test.o
rm encfsctl.o
mv *.o .umfuse/
gcc -shared -o umfuseencfs .umfuse/*.o -lssl -lcrypto -ldl -lpthread -lfuse -lrlog -lasprintf && echo "umfuseencfs created"
