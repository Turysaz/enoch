CC = gcc
OBJECTS = src/shaftoe.o src/pontifex.o src/px_crypto.o
TESTOBJECTS = src/pontifex.o test/pontifex_tests.o \
				test/tests_main.o
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
NAME = shaftoe

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

