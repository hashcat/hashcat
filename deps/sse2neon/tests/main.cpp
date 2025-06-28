#include <stdint.h>
#include <stdio.h>
#include "impl.h"

int main(int /*argc*/, const char ** /*argv*/)
{
    SSE2NEON::SSE2NEONTest *test = SSE2NEON::SSE2NEONTest::create();
    uint32_t passCount = 0;
    uint32_t failedCount = 0;
    uint32_t ignoreCount = 0;
    for (uint32_t i = 0; i < SSE2NEON::it_last; i++) {
        SSE2NEON::InstructionTest it = SSE2NEON::InstructionTest(i);
        SSE2NEON::result_t ret = test->runTest(it);
        // If the test fails, we will run it again so we can step into the
        // debugger and figure out why!
        if (ret == SSE2NEON::TEST_FAIL) {
            printf("Test %-30s failed\n", SSE2NEON::instructionString[it]);
            failedCount++;
        } else if (ret == SSE2NEON::TEST_UNIMPL) {
            printf("Test %-30s skipped\n", SSE2NEON::instructionString[it]);
            ignoreCount++;
        } else {
            printf("Test %-30s passed\n", SSE2NEON::instructionString[it]);
            passCount++;
        }
    }
    test->release();
    printf(
        "SSE2NEONTest Complete!\n"
        "Passed:  %d\n"
        "Failed:  %d\n"
        "Ignored: %d\n"
        "Coverage rate: %.2f%%\n",
        passCount, failedCount, ignoreCount,
        (float) passCount / (float) (passCount + failedCount + ignoreCount) *
            100);

    return failedCount ? -1 : 0;
}
