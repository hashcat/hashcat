#ifndef HWMON_TEST_H
#define HWMON_TEST_H

#include <iostream>

#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>

extern "C" {
	#include "types.h"
}

class HwmonTest : public CppUnit::TestFixture{
private:
	hashcat_ctx_t *ctx;
	void restoreCtx();
public:
	void setUp();
	void tearDown();
	static CppUnit::Test *suite();
	void disabledHwmon();
	void showVersion();
	void showUsage();
	void stdout();
	void exampleHashes();
};

#endif
