
#include <stdlib.h>
#include <CUnit/CUnit.h>
#include "./px_io_tests.h"
#include "../src/px_io.h"

extern int loglevel;

void read_key_raw(void) {
    int result;
    char key[54];
    const char expected[54] =
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
    char key[54];
    const char *keystr_1 =
        "01020304050607080910"
        "11121314151617181920"
        "21222324252627282930"
        "31323334353637383940"
        "41424344454647484950"
        "5152535";

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


    return 0;
}


