#!/bin/bash

#  valgrind-tests.sh : runs various Valgrind test cases
#
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

echo_red() {
    echo -e "\e[31m$1\e[0m"
}

testrunner="\
    valgrind \
      --leak-check=full \
      --quiet \
      --error-exitcode=-1"
      #--show-error-list=yes

fail=0

echo_red "Run unit tests"
$testrunner ./testrunner
[ $? -eq "0" ] || fail=1

#====================================================================
echo_red "Stream tests with password"
# Without move-jokers
$testrunner ./enoch -q -s 100 -p abcde
[ $? -eq "0" ] || fail=1
# With move-jokers
$testrunner ./enoch -q -s 100 -jp abcde
[ $? -eq "0" ] || fail=1

#====================================================================
echo_red "Encryption test"
$testrunner ./enoch -q -p cryptonomicon -i <(echo solitaire)
[ $? -eq "0" ] || fail=1

#====================================================================
echo_red "Decryption test"

# raw decryption
$testrunner ./enoch -rdqp cryptonomicon -i <(echo 'KIRAK SFJAN')
[ $? -eq "0" ] || fail=1

# with frame
$testrunner ./enoch -dqp cryptonomicon -i <(cat << EOF
foo
-----BEGIN PONTIFEX MESSAGE-----
KIRAK SFJAN
-----END PONTIFEX MESSAGE-----
bar
EOF
)
[ $? -eq "0" ] || fail=1

# malformed
$testrunner ./enoch -dqp cryptonomicon -i <(cat << EOF
foo
-----BEGIN PONTIFEX MESSAGE-----
KIRAK SFJAN
FOOOOOO
bar
EOF
)
[ $? -eq "0" ] || fail=1



#====================================================================
echo_red "Print key test"
$testrunner ./enoch -q -p foobar --gen-key
[ $? -eq "0" ] || fail=1

#====================================================================
echo_red "Read key tests"
# key too short
$testrunner ./enoch -s 20 -k 0102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253
# key okay
[ $? -eq "-1" ] && fail=1
$testrunner ./enoch -s 20 -k 010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354
[ $? -eq "-1" ] && fail=1
# key too long
$testrunner ./enoch -s 20 -k 01020304050607080910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535401
[ $? -eq "-1" ] && fail=1

echo
if [[ $fail == "0" ]]; then
    echo -e "\e[32mAll good :)\e[0m"
else
    echo_red "Test failed"
fi

