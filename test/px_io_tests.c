
#include <stdlib.h>
#include <CUnit/CUnit.h>
#include "./px_io_tests.h"
#include "../src/px_io.h"

void dummy_test(void) {
    return;
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
        "Dummy test",
        dummy_test);

    return 0;
}


