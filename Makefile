C=gcc
CFLAGS=-ggdb

all: benchmarkDNS  hashaddr  hashdns

benchmarkDNS.o: benchmarkDNS.c

hashaddr.o: hashaddr.c

hashdns.o: hashdns.c

benchmarkDNS: benchmarkDNS.o
	$(CC) -ggdb -o $@ $< -lmhash

hashaddr: hashaddr.o
	$(CC) -ggdb -o $@ $< -lmhash

hashdns: hashdns.o
	$(CC) -ggdb -o $@ $< -lmhash -llwipv6

clean:
	rm -f *.o benchmarkDNS  hashaddr  hashdns
