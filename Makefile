CC=gcc

all: otipaddr otipfwd otipweb otipdns vderadvd

otipaddr.o: otipaddr.c

otipfwd.o: otipfwd.c

otipweb.o: otipweb.c

otipdns.o: otipdns.c

vderadvd.o: vderadvd.c

otipaddr: otipaddr.o
	$(CC) -ggdb -o $@ $< -lmhash

otipfwd: otipfwd.o
	$(CC) -ggdb -o $@ $< -lmhash -llwipv6

otipweb: otipweb.o
	$(CC) -ggdb -o $@ $< -lmhash -llwipv6

otipdns: otipdns.o
	$(CC) -ggdb -o $@ $< -lmhash -llwipv6

vderadvd: vderadvd.o
	$(CC) -ggdb -o $@ $< -lvdeplug

clean:
	rm -f *.o otipaddr otipfwd otipweb otipdns vderadvd
