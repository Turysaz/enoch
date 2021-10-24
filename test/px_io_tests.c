/*
 *  Implementation of Bruce Schneier's Pontifex/Solitaire cryptosystem.
 *  Copyright (C) 2021 Turysaz
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdlib.h>
#include <CUnit/CUnit.h>
#include "./px_io_tests.h"
#include "../src/px_common.h"
#include "../src/px_io.h"

extern int loglevel;

void read_key_raw(void) {
    int result;
    card key[54];
    const card expected[54] =
        { 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,
         13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
         25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
         37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
         49, 50, 51, 52, 53, 54 };
    const char *keystr =
        "01020304050607080910"
        "11121314151617181920"
        "21222324252627282930"
        "31323334353637383940"
        "41424344454647484950"
        "51525354";

    result = px_rdkey(keystr, key);

    CU_ASSERT_NSTRING_EQUAL(key, expected, 54);
    CU_ASSERT_EQUAL(result, 0);
}

void read_key_raw_too_short(void) {
    int result;
    card key[54];
    /* This key is one byte too short */
    const char *keystr_1 =
        "01020304050607080910"
        "11121314151617181920"
        "21222324252627282930"
        "31323334353637383940"
        "41424344454647484950"
        "5152535";

   /* This key is two bytes too short */
   const char *keystr_2 =
        "01020304050607080910"
        "11121314151617181920"
        "21222324252627282930"
        "31323334353637383940"
        "41424344454647484950"
        "515253";

    result = px_rdkey(keystr_1, key);
    CU_ASSERT_EQUAL(result, -1);
    result = px_rdkey(keystr_2, key);
    CU_ASSERT_EQUAL(result, -1);
}

void read_key_with_invalid_characters(void) {
    int result;
    card key[54];
    const char *keystr_1 =
        "01020304050607080910"
        "11121314151617181920"
        "2122232xxxxx27282930"
        "31323334353637383940"
        "41424344454647484950"
        "51525354";

    result = px_rdkey(keystr_1, key);
    CU_ASSERT_EQUAL(result, -1);
}



void read_happy_cipher_message(void) {
    int result;
    char *buf;

    const char *message =
        "-----BEGIN PONTIFEX MESSAGE-----\n"
        "ABCDE ABCDE ABCDE ABCDE ABCDE ABCDE\n"
        "ABCDE ABCDE ABCDE ABCDE ABCDE ABCDE\n"
        "-----END PONTIFEX MESSAGE-----\n";
    const char *expected =
        "ABCDEABCDEABCDEABCDEABCDEABCDE"
        "ABCDEABCDEABCDEABCDEABCDEABCDE";

    result = px_rdcipher(message, &buf);

    CU_ASSERT_EQUAL(result, 61);
    CU_ASSERT_STRING_EQUAL(buf, expected);

    if(buf) free(buf);
}

void read_cipher_message_from_noise(void) {
    int result;
    char *buf;

    const char *message =
        "Foo this is part of an email!!"
        "-----BEGIN PONTIFEX MESSAGE-----\n"
        "ABCDE ABCDE ABCDE ABCDE ABCDE ABCDE\n"
        "ABCDE ABCDE ABCDE ABCDE ABCDE ABCDE\n"
        "XYZAB"
        "-----END PONTIFEX MESSAGE----- and the\n"
        "message is in between!\n\n";
    const char *expected =
        "ABCDEABCDEABCDEABCDEABCDEABCDE"
        "ABCDEABCDEABCDEABCDEABCDEABCDE"
        "XYZAB";

    result = px_rdcipher(message, &buf);

    CU_ASSERT_EQUAL(result, 66);
    CU_ASSERT_STRING_EQUAL(buf, expected);

    if(buf) free(buf);
}

void read_cipher_message_missing_start(void) {
    int result;
    char *buf;

    const char *message =
        "This message lacks the start"
        "ABCDE ABCDE ABCDE ABCDE ABCDE ABCDE\n"
        "XYZAB"
        "-----END PONTIFEX MESSAGE-----\n";

    result = px_rdcipher(message, &buf);
    CU_ASSERT_EQUAL(result, -1);

    if (buf) free(buf);
}

void read_cipher_message_missing_end(void) {
    int result;
    char *buf;

    const char *message =
        "This message lacks the end"
        "-----BEGIN PONTIFEX MESSAGE-----\n"
        "ABCDE ABCDE ABCDE ABCDE ABCDE ABCDE\n"
        "XYZAB";

    result = px_rdcipher(message, &buf);
    CU_ASSERT_EQUAL(result, -1);

    if(buf) free(buf);
}

void read_cipher_message_wrong_order(void) {
    int result;
    char *buf;

    const char *message =
        "This message lacks the end"
        "-----END PONTIFEX MESSAGE-----\n"
        "ABCDE ABCDE ABCDE ABCDE ABCDE ABCDE\n"
        "XYZAB"
        "-----BEGIN PONTIFEX MESSAGE-----\n"
        "foo";

    result = px_rdcipher(message, &buf);
    CU_ASSERT_EQUAL(result, -1);

    if(buf) free(buf);
}

void read_empty_cipher_message(void) {
    int result;
    char *buf;

    const char *message =
        "This message lacks content :)"
        "-----BEGIN PONTIFEX MESSAGE-----\n"
        "-----END PONTIFEX MESSAGE-----\n"
        "only noise around it.";

    result = px_rdcipher(message, &buf);
    CU_ASSERT_EQUAL(result, 1);
    CU_ASSERT_EQUAL(strlen(buf), 0);

    if(buf) free(buf);
}

/* ========================================================= */

static int initsuite_px_io(void) {
    return 0;
}

static int cleansuite_px_io(void) {
    return 0;
}

int addsuite_px_io(void) {
    CU_pSuite suite;
    suite = CU_add_suite(
        "Pontifex I/O operations tests",
        initsuite_px_io, cleansuite_px_io);

    if (suite == NULL) {
        return -1;
    }

    CU_add_test(
        suite,
        "Read key from raw string",
        read_key_raw);
    CU_add_test(
        suite,
        "Read too short keys from raw string",
        read_key_raw_too_short);
    CU_add_test(
        suite,
        "Read key with invalid characters",
        read_key_with_invalid_characters);

    CU_add_test(
        suite,
        "Read happy cipher message",
        read_happy_cipher_message);
    CU_add_test(
        suite,
        "Read cipher message from noise",
        read_cipher_message_from_noise);
    CU_add_test(
        suite,
        "Read cipher with missing start",
        read_cipher_message_missing_start);
    CU_add_test(
        suite,
        "Read cipher message with missing end",
        read_cipher_message_missing_end);
    CU_add_test(
        suite,
        "Read cipher message with end before start",
        read_cipher_message_wrong_order);
    CU_add_test(
        suite,
        "Read empty cipher message",
        read_empty_cipher_message);

    return 0;
}

