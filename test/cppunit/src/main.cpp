#include <cppunit/ui/text/TestRunner.h>
#include "hwmon_test.h"

int main(){
	CppUnit::TextUi::TestRunner runner;
	runner.addTest(HwmonTest::suite());
	runner.run();
	return 0;
}
