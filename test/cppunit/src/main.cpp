#include <cppunit/ui/text/TestRunner.h>
#include "hwmon_test.h"
#include "convert_test.h"
#include "hashes_test.h"
#include "sort_test.h"
#include "salt_test.h"

int main(){
	CppUnit::TextUi::TestRunner runner;

	/*
	 * Unit:        Hwmon
	 * Test state:  All tests pass
	 */
	runner.addTest(HwmonTest::suite());

	/*
	 * Unit:        Convert
	 * Test state:  Three tests fail. The base64 string
	 *              validity checker is not robust at all.
	 *              It fails to check for valid lengths and
	 *              padding.
	 */
	runner.addTest(ConvertTest::suite());

        runner.addTest(HashesTest::suite());
        runner.addTest(SortTest::suite());
        runner.addTest(SaltTest::suite());

	// Run tests
	runner.run();
	return 0;
}
