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

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "./px_crypto_tests.h"
#include "./px_io_tests.h"
#include "./px_common_tests.h"

int loglevel = -1;

int main(int argc, char **argv) {
   if (CUE_SUCCESS != CU_initialize_registry()) {
       return CU_get_error();
   }

   if (addsuite_px_common() == -1) goto cleanup;
   if (addsuite_px_crypto() == -1) goto cleanup;
   if (addsuite_px_io() == -1) goto cleanup;

   CU_basic_set_mode(CU_BRM_VERBOSE);
   CU_basic_run_tests();

cleanup:
   CU_cleanup_registry();
   return CU_get_error();
}

