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
#include "./px_common_tests.h"
#include "../src/px_common.h"

void ascii2card_cases(void) {
    CU_ASSERT_EQUAL(CARD2ASCII( 1), 'A');
    CU_ASSERT_EQUAL(CARD2ASCII( 2), 'B');
    CU_ASSERT_EQUAL(CARD2ASCII( 3), 'C');
    CU_ASSERT_EQUAL(CARD2ASCII(26), 'Z');
    CU_ASSERT_EQUAL(CARD2ASCII(27), 'A');
    CU_ASSERT_EQUAL(CARD2ASCII(28), 'B');
    CU_ASSERT_EQUAL(CARD2ASCII(29), 'C');
    CU_ASSERT_EQUAL(CARD2ASCII(52), 'Z');
}

void card2ascii_cases(void) {
    CU_ASSERT_EQUAL(ASCII2CARD('A'),  1);
    CU_ASSERT_EQUAL(ASCII2CARD('a'),  1);
    CU_ASSERT_EQUAL(ASCII2CARD('B'),  2);
    CU_ASSERT_EQUAL(ASCII2CARD('b'),  2);
    CU_ASSERT_EQUAL(ASCII2CARD('Y'), 25);
    CU_ASSERT_EQUAL(ASCII2CARD('y'), 25);
    CU_ASSERT_EQUAL(ASCII2CARD('Z'), 26);
    CU_ASSERT_EQUAL(ASCII2CARD('z'), 26);
}

/* ========================================================= */

static int initsuite_px_common(void) {
    return 0;
}

static int cleansuite_px_common(void) {
    return 0;
}

int addsuite_px_common(void) {
    CU_pSuite suite;
    suite = CU_add_suite(
        "Pontifex common API tests",
        initsuite_px_common, cleansuite_px_common);

    if (suite == NULL) {
        return -1;
    }

    CU_add_test(
        suite,
        "CARD2ASCII: Multiple test cases",
        card2ascii_cases);
    CU_add_test(
        suite,
        "ASCII2CARD: Multiple test cases",
        ascii2card_cases);

    return 0;
}


