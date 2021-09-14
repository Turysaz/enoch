CC = gcc
OBJECTS = src/enoch.o  src/px_crypto.o src/px_io.o
TESTOBJECTS = test/px_crypto_tests.o test/tests_main.o src/px_crypto.o
LIBS =
TESTLIBS = -lcunit
CFLAGS = \
		-g \
		-Wall \
		-ansi \
		-pedantic \
		-pedantic-errors \
		#-Wno-variadic-macros \
		#-Wno-gnu-zero-variadic-macro-arguments
BINDIR = $(DESTDIR)/usr/bin
NAME = enoch

all : $(NAME) $(TESTOBJECTS)
	$(CC) -o testrunner $(TESTOBJECTS) $(TESTLIBS)
	./testrunner

$(NAME) : $(OBJECTS)
	$(CC) -o $(NAME) $(OBJECTS) $(LIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

install:
	install -mode=755 $(NAME) $(BINDIR)/

clean:
	rm src/*.o
	rm test/*.o
	rm $(NAME)
	rm testrunner
	
uninstall:
	rm $(BINDIR)/$(NAME)

