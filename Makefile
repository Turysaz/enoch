#  Implementation of Bruce Schneier's Pontifex/Solitaire cryptosystem.
#  Copyright (C) 2021 Turysaz
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, write to the Free Software Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

CC = gcc
OBJECTS = src/enoch.o src/px_crypto.o src/px_io.o
TESTOBJECTS = \
	test/px_crypto_tests.o \
	test/px_io_tests.o \
	test/tests_main.o \
	src/px_crypto.o \
	src/px_io.o
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

all : $(NAME) unittests

valgrind: $(NAME) testrunner
	bash ./valgrind-tests.sh

testrunner: $(TESTOBJECTS)
	$(CC) -o testrunner $(TESTOBJECTS) $(TESTLIBS)

unittests: testrunner
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

