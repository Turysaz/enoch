
#include <CUnit/CUnit.h>
#include "./px_crypto_tests.h"
#include "../src/px_crypto.h"

int loglevel = 0;

const char key01[] = 
    { 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,
     13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
     25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
     37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
     49, 50, 51, 52, 53, 54 };


/* ========================================================= */

static void schneier_testvector_01(void) {
    struct px_opts opts = { 1 };
    int result;
    char *buf = NULL;
    
    result = px_encrypt(
        key01,
        "aaaaa aaaaa aaaaa",
        3*5+2+1, /* 3*5 'a's, two spaces and one 0-terminator. */
        &buf,
        &opts);

    CU_ASSERT_STRING_EQUAL(buf, "EXKYIZSGEHUNTIQ");
    CU_ASSERT_EQUAL(result, 16);
}

/* ========================================================= */

static int initsuite_px_crypto(void) {
    return 0;
}

static int cleansuite_px_crypto(void) {
    return 0;
}

int addsuite_px_crypto(void) {
    CU_pSuite suite;
    suite = CU_add_suite(
        "Pontifex crypto algorithm tests",
        initsuite_px_crypto, cleansuite_px_crypto);

    if (suite == NULL) {
        return -1;
    }

    CU_add_test(suite,
        "Test Schneier's test vector 1",
        schneier_testvector_01);

    return 0;
}

