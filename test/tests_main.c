
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "./px_crypto_tests.h"

int main(int argc, char **argv) {
   if (CUE_SUCCESS != CU_initialize_registry()) {
       return CU_get_error();
   }

   if (addsuite_px_crypto() == -1) goto cleanup;

   CU_basic_set_mode(CU_BRM_VERBOSE);
   CU_basic_run_tests();

cleanup:
   CU_cleanup_registry();
   return CU_get_error();
}
