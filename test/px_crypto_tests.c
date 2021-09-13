
#include <stdlib.h>
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

struct s_tvxx {
    const char *pt; /* plain text */
    const char *pw; /* password */
    const char *ct; /* cipher text */
    const char *dc; /* decrypted */
};

/* Test vectors provided by Bruce Schneier himself. */
static struct s_tvxx testvectors[] = {
    {"AAAAAAAAAAAAAAA", "", "EXKYIZSGEHUNTIQ", "AAAAAAAAAAAAAAA"},
    {"AAAAAAAAAAAAAAA", "f", "XYIUQBMHKKJBEGY", "AAAAAAAAAAAAAAA"},
    {"AAAAAAAAAAAAAAA", "fo", "TUJYMBERLGXNDIW", "AAAAAAAAAAAAAAA"},
    {"AAAAAAAAAAAAAAA", "foo", "ITHZUJIWGRFARMW", "AAAAAAAAAAAAAAA"},
    {"AAAAAAAAAAAAAAA", "a", "XODALGSCULIQNSC", "AAAAAAAAAAAAAAA"},
    {"AAAAAAAAAAAAAAA", "aa", "OHGWMXXCAIMCIQP", "AAAAAAAAAAAAAAA"},
    {"AAAAAAAAAAAAAAA", "aaa", "DCSQYHBQZNGDRUT", "AAAAAAAAAAAAAAA"},
    {"AAAAAAAAAAAAAAA", "b", "XQEEMOITLZVDSQS", "AAAAAAAAAAAAAAA"},
    {"AAAAAAAAAAAAAAA", "bc", "QNGRKQIHCLGWSCE", "AAAAAAAAAAAAAAA"},
    {"AAAAAAAAAAAAAAA", "bcd", "FMUBYBMAXHNQXCJ", "AAAAAAAAAAAAAAA"},
    {
        "AAAAAAAAAAAAAAAAAAAAAAAAA",
        "cryptonomicon",
        "SUGSRSXSWQRMXOHIPBFPXARYQ",
        "AAAAAAAAAAAAAAAAAAAAAAAAA"
    },
    {"SOLITAIRE", "cryptonomicon", "KIRAKSFJAN", "SOLITAIREX"}
};

/* ========================================================= */

static void encrypt_message_too_long(void) {
    struct px_opts opts = { 1 };
    int result;
    char *buf = NULL;

    result = px_encrypt(
        key01,
        "aaaaaaaa", /* 8 characters */
        5,
        &buf,
        &opts);

    CU_ASSERT_STRING_EQUAL(buf, "EXKYI"); /* <- only 5 characters*/
    CU_ASSERT_EQUAL(result, 5);

    if (buf) free(buf);
}

static void encrypt_message_too_short(void) {
    struct px_opts opts = { 1 };
    int result;
    char *buf = NULL;

    result = px_encrypt(
        key01,
        "aaa",
        20, /* whoops */
        &buf,
        &opts);

    CU_ASSERT_STRING_EQUAL(buf, "EXKYI"); /* <- only 5 characters */
    CU_ASSERT_EQUAL(result, 5);

    if (buf) free(buf);
}

static void encrypt_tv_by_key(void) {
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

    if (buf) free(buf);
}

static void encrypt_testvectors_by_pw() {
    int i, tvlen;
    const struct px_opts opts = { 1 };
    int res_keygen = -1,
        res_encr = -1;
    char key[54];
    char *buf = NULL;
    struct s_tvxx *s;

    tvlen = sizeof(testvectors) / sizeof(struct s_tvxx);

    for(i = 0; i < tvlen; i++) {
        s = &testvectors[i];

        res_keygen = px_keygen(s->pw, 0, key);
        CU_ASSERT_EQUAL_FATAL(res_keygen, 0);

        res_encr = px_encrypt(key, s->pt, strlen(s->pt), &buf, &opts);

        CU_ASSERT_STRING_EQUAL(buf, s->ct);
        CU_ASSERT_EQUAL(res_encr, strlen(s->ct) + 1);

        if (buf) free(buf);
    }
}

static void decrypt_testvectors_by_pw() {
    int i, tvlen;
    const struct px_opts opts = { 1 };
    int res_keygen = -1,
        res_encr = -1;
    char key[54];
    char *buf = NULL;
    struct s_tvxx *s;

    tvlen = sizeof(testvectors) / sizeof(struct s_tvxx);

    for(i = 0; i < tvlen; i++) {
        s = &testvectors[i];

        res_keygen = px_keygen(s->pw, 0, key);
        CU_ASSERT_EQUAL_FATAL(res_keygen, 0);

        res_encr = px_decrypt(key, s->ct, strlen(s->ct), &buf, &opts);

        CU_ASSERT_STRING_EQUAL(buf, s->dc);
        CU_ASSERT_EQUAL(res_encr, strlen(s->dc) + 1);

        if (buf) free(buf);
    }
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
        "Encrypt: message longer than specified",
        encrypt_message_too_long);
    CU_add_test(
        suite,
        "Encrypt: message shorter than specified",
        encrypt_message_too_short);
    CU_add_test(
        suite,
        "Encrypt: Schneier's test vector 01 by key",
        encrypt_tv_by_key);
    CU_add_test(
        suite,
        "Encrypt: Schneier's test vectors by password",
        encrypt_testvectors_by_pw);
    CU_add_test(
        suite,
        "Decrypt: Schneier's test vectors by password",
        decrypt_testvectors_by_pw);

    return 0;
}
