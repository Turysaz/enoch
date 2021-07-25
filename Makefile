CC = gcc
OBJECTS = src/shaftoe.o src/pontifex.o
LIBS =
CFLAGS = \
		-g \
		-Wall \
		-ansi \
		-pedantic \
		-pedantic-errors \
		#-Wno-variadic-macros \
		#-Wno-gnu-zero-variadic-macro-arguments
BINDIR = $(DESTDIR)/usr/bin
NAME = shaftoe

$(NAME) : $(OBJECTS)
	$(CC) -o $(NAME) $(OBJECTS) $(LIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

install:
	install -mode=755 $(NAME) $(BINDIR)/

clean:
	rm src/*.o $(NAME)
	
uninstall:
	rm $(BINDIR)/$(NAME)

