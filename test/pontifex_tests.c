
#include <CUnit/CUnit.h>
#include "./pontifex_tests.h"
#include "../src/pontifex.h"

int loglevel = 0;

static int initsuite_pontifex(void) {
    return 0;
}

static int cleansuite_pontifex(void) {
    return 0;
}

/* ========================================================= */

static void defaultopts_as_expected(void) {
    struct px_opts sut;

    sut = px_defaultopts();

    CU_ASSERT_EQUAL(sut.mode, PX_ENCR);
    CU_ASSERT_EQUAL(sut.input, stdin);
    CU_ASSERT_EQUAL(sut.output, stdout);
    CU_ASSERT_FALSE(sut.raw);
    CU_ASSERT_FALSE(sut.movjok);
    CU_ASSERT_EQUAL(sut.length, 5);
}

/* ========================================================= */

int addsuite_pontifex(void) {
    CU_pSuite suite;
    suite = CU_add_suite(
        "Pontifex algorithm tests",
        initsuite_pontifex, cleansuite_pontifex);

    if (suite == NULL) {
        return -1;
    }

    CU_add_test(suite,
        "Defaults for px_opts are valid",
        defaultopts_as_expected);

    return 0;
}

