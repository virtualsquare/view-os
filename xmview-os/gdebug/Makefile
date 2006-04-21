OBJS=gdebug.o
CFLAGS=-g -ggdb -I../include
CPPFLAGS=-I../include

all: libgdebug.a

libgdebug.a: $(OBJS)
	rm -f "$@"
	ar rcs "$@" $?
	ranlib "$@"

%.d: %.c
	@set -e; $(CC) -MM $(CPPFLAGS) $(@:.d=.c) | sed 's/\($*\)\.o[ :]*/\1.o $@ : /g' > $@; [ -s $@ ] || rm -f $@

-include $(OBJS:.o=.d)

clean:	
	rm -f *.o *.a

distclean: clean
	rm -f *.d

install:

.PHONY: all clean distclean install
