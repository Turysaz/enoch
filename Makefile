CC = clang
OBJECTS = pontifex.o
LIBS = ""
CFLAGS = \
		-Wall \
		-ansi \
		-pedantic \
		-pedantic-errors \
		-Wno-variadic-macros \
		-Wno-gnu-zero-variadic-macro-arguments
BINDIR = $(DESTDIR)/usr/bin
NAME = pfex

$(NAME) : $(OBJECTS)
	$(CC) -o $(NAME) $(OBJECTS) $(LIBS)
%.o: %.c
	$(CC) -c $(CFLAGS) $<

install:
	install -mode=755 $(NAME) $(BINDIR)/

clean:
	rm *.o $(NAME)
	
uninstall:
	rm $(BINDIR)/$(NAME)

