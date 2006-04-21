all: syscallnames.h

syscallnames.h: syscallnames.sh
	./syscallnames.sh

install:

.PHONY: all clean install distclean

distclean: clean

clean:
	rm -f syscallnames.h

