#ifndef HWMON_TEST_H
#define HWMON_TEST_H

#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>

extern "C" {
	#ifndef _TYPES_H
    #include "types.h"
    #endif
}

/*
 *
 * Class:   HwmonTest
 * Desc:    Tests hashcat hwmon context initialization.
 * 			This is really all that can be unit tested,
 * 			as all of the other public interface methods
 *			vary depending on the hardware, OS, and system
 * 			libraries available. Only the context initialization
 * 			has multiple platform-independent test cases.
 *
 */
class HwmonTest : public CppUnit::TestFixture{
private:
	hashcat_ctx_t *ctx;
	void initCtx();
	void freeCtx();
	void restoreCtx();
	void disabledHwmon();
	void showVersion();
	void showUsage();
	void stdout();
	void exampleHashes();
public:
	void setUp();
	void tearDown();
	static CppUnit::Test *suite();
};

#endif
