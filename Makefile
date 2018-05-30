CC	?=  gcc
CFLAGS	+=  -g -O3 -W -D"_LARGEFILE64_SOURCE" -D"_FILE_OFFSET_BITS=64" -D"__MSVCRT__" -D"__USE_MINGW_FSEEK"
LDLIBS  = -lz
FILES	=	pupunpack unpkg unpfs trophy trp_resigner genidx undat fpkg_rename
COMMON	=	sha2.o mingw_mmap.o tools.o aes.o sha1.o
DEPS	=	Makefile sha2.h

OBJS	= $(COMMON) $(addsuffix .o, $(FILES))

all: $(FILES)

$(FILES): %: %.o $(COMMON) $(DEPS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(COMMON) $(LDLIBS)

$(OBJS): %.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(FILES) *.exe *~
