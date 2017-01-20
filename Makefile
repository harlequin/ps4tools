CC	=  gcc
CFLAGS	=  -g -O2 -Wall
LDLIBS  = -lz
FILES	=	pupunpack unpkg unpfs trophy trp_resigner
COMMON	=	sha2.o mingw_mmap.o tools.o aes.o sha1.o
DEPS	=	Makefile sha2.h

OBJS	= $(COMMON) $(addsuffix .o, $(FILES))

all: $(FILES)

$(FILES): %: %.o $(COMMON) $(DEPS)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON) $(LDLIBS)

$(OBJS): %.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(FILES) *.exe *~
