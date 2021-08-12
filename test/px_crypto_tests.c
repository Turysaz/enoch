
#include <CUnit/CUnit.h>
#include "./px_crypto_tests.h"
#include "../src/px_crypto.h"

int loglevel = 0;

const char key01 [] = 
    { 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,
     13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
     25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
     37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
     49, 50, 51, 52, 53, 54 };


/* ========================================================= */

/* Bruce Schneiers test vectors */

static void _encrypt_tvxx_pw(
    const char *message,
    const char *password,
    const char *expected) {

    struct px_opts opts = { 1 };
    int res_keygen = -1,
        res_encr = -1;
    char key[54];
    char *buf = NULL;
    
    res_keygen = px_keygen(password, 0, key);
    CU_ASSERT_EQUAL_FATAL(res_keygen, 0);

    res_encr = px_encrypt(key, message, strlen(message), &buf, &opts);

    CU_ASSERT_STRING_EQUAL(buf, expected);
    CU_ASSERT_EQUAL(res_encr, strlen(expected) + 1);
}

static void encrypt_tv01_key(void) {
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

static void encrypt_tv01_pw(void) {
    const char *message = "AAAAAAAAAAAAAAA";
    struct px_opts opts = { 1 };
    int res_keygen = -1,
        res_encr = -1;
    char key[54];
    char *buf = NULL;
     
    res_keygen = px_keygen("", 0, key);
    CU_ASSERT_EQUAL_FATAL(res_keygen, 0);

    res_encr = px_encrypt(key, message, strlen(message), &buf, &opts);

    CU_ASSERT_STRING_EQUAL(buf, "EXKYIZSGEHUNTIQ");
    CU_ASSERT_EQUAL(res_encr, 16);
}

static void encrypt_tv02_pw(void) {
    _encrypt_tvxx_pw("AAAAAAAAAAAAAAA", "f", "XYIUQBMHKKJBEGY");
}

static void encrypt_tv03_pw(void) {
    _encrypt_tvxx_pw("AAAAAAAAAAAAAAA", "fo", "TUJYMBERLGXNDIW");
}

static void encrypt_tv04_pw(void) {
    _encrypt_tvxx_pw("AAAAAAAAAAAAAAA", "foo", "ITHZUJIWGRFARMW");
}

static void encrypt_tv05_pw(void) {
    _encrypt_tvxx_pw("AAAAAAAAAAAAAAA", "a", "XODALGSCULIQNSC");
}

static void encrypt_tv06_pw(void) {
    _encrypt_tvxx_pw("AAAAAAAAAAAAAAA", "aa", "OHGWMXXCAIMCIQP");
}

static void encrypt_tv07_pw(void) {
    _encrypt_tvxx_pw("AAAAAAAAAAAAAAA", "aaa", "DCSQYHBQZNGDRUT");
}

static void encrypt_tv08_pw(void) {
    _encrypt_tvxx_pw("AAAAAAAAAAAAAAA", "b", "XQEEMOITLZVDSQS");
}

static void encrypt_tv09_pw(void) {
    _encrypt_tvxx_pw("AAAAAAAAAAAAAAA", "bc", "QNGRKQIHCLGWSCE");
}

static void encrypt_tv10_pw(void) {
    _encrypt_tvxx_pw("AAAAAAAAAAAAAAA", "bcd", "FMUBYBMAXHNQXCJ");
}

static void encrypt_tv11_pw(void) {
    _encrypt_tvxx_pw(
        "AAAAAAAAAAAAAAAAAAAAAAAAA",
        "cryptonomicon",
        "SUGSRSXSWQRMXOHIPBFPXARYQ");
}

static void encrypt_tv12_pw(void) {
    _encrypt_tvxx_pw("SOLITAIRE", "cryptonomicon", "KIRAKSFJAN");
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

    CU_add_test(
        suite,
        "Encrypt: Schneier's test vector 01 by key",
        encrypt_tv01_key);

    CU_add_test(
        suite,
        "Encrypt: Schneier's test vector 01 by password",
        encrypt_tv01_pw);

    CU_add_test(
        suite,
        "Encrypt: Schneier's test vector 02 by password",
        encrypt_tv02_pw);

    CU_add_test(
        suite,
        "Encrypt: Schneier's test vector 03 by password",
        encrypt_tv03_pw);

    CU_add_test(
        suite,
        "Encrypt: Schneier's test vector 04 by password",
        encrypt_tv04_pw);

    CU_add_test(
        suite,
        "Encrypt: Schneier's test vector 05 by password",
        encrypt_tv05_pw);

    CU_add_test(
        suite,
        "Encrypt: Schneier's test vector 06 by password",
        encrypt_tv06_pw);

    CU_add_test(
        suite,
        "Encrypt: Schneier's test vector 07 by password",
        encrypt_tv07_pw);

    CU_add_test(
        suite,
        "Encrypt: Schneier's test vector 08 by password",
        encrypt_tv08_pw);

    CU_add_test(
        suite,
        "Encrypt: Schneier's test vector 09 by password",
        encrypt_tv09_pw);

    CU_add_test(
        suite,
        "Encrypt: Schneier's test vector 10 by password",
        encrypt_tv10_pw);

    CU_add_test(
        suite,
        "Encrypt: Schneier's test vector 11 by password",
        encrypt_tv11_pw);

    CU_add_test(
        suite,
        "Encrypt: Schneier's test vector 12 by password",
        encrypt_tv12_pw);


    return 0;
}

