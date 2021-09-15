#!/bin/bash

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
