#include <iostream>

#include <cppunit/TestFixture.h>
#include <cppunit/TestCase.h>
#include <cppunit/TestCaller.h>
#include <cppunit/TestSuite.h>

#include "hwmon_test.h"

extern "C" {
	#include "hwmon.h"
	#include "memory.h"
}

using std::cout;
using std::string;

void HwmonTest::setUp(){
	printf("%s\n", "Setting up HwmonTest environment");
	ctx = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));
	ctx->hwmon_ctx = (hwmon_ctx_t *) malloc(sizeof(hwmon_ctx_t));
	ctx->user_options = (user_options_t *) malloc(sizeof(user_options_t));
	ctx->opencl_ctx = (opencl_ctx_t *) malloc(sizeof(opencl_ctx_t));
}

void HwmonTest::tearDown(){
	printf("%s\n", "Tearing down HwmonTest environment");
	free(ctx->hwmon_ctx);
	free(ctx->user_options);
	free(ctx->opencl_ctx);
	free(ctx);
}

void HwmonTest::restoreCtx(){
	ctx->user_options->example_hashes = false;
	ctx->user_options->keyspace = false;
	ctx->user_options->left = false;
	ctx->user_options->opencl_info = false;
	ctx->user_options->show = false;
	ctx->user_options->stdout_flag = false;
	ctx->user_options->usage = false;
	ctx->user_options->version = false;
	ctx->user_options->hwmon_disable = false;

	ctx->opencl_ctx->need_nvml = false;
	ctx->opencl_ctx->need_nvapi = false;
	ctx->hwmon_ctx->hm_nvml = NULL;
	ctx->opencl_ctx->need_adl = false;
	ctx->opencl_ctx->need_sysfs = false;
	ctx->hwmon_ctx->hm_adl = NULL;
}

CppUnit::Test *HwmonTest::suite(){
	CppUnit::TestSuite* suite = new CppUnit::TestSuite("Hwmon Test");
	suite->addTest(new CppUnit::TestCaller<HwmonTest>("disabledHwmon", &HwmonTest::disabledHwmon));
	suite->addTest(new CppUnit::TestCaller<HwmonTest>("showVersion", &HwmonTest::showVersion));
	suite->addTest(new CppUnit::TestCaller<HwmonTest>("showUsage", &HwmonTest::showUsage));
	suite->addTest(new CppUnit::TestCaller<HwmonTest>("stdout", &HwmonTest::stdout));
	suite->addTest(new CppUnit::TestCaller<HwmonTest>("exampleHashes", &HwmonTest::exampleHashes));
	return suite;
}

void HwmonTest::disabledHwmon(){
	restoreCtx();
	ctx->user_options->hwmon_disable = true;
	CPPUNIT_ASSERT(!hwmon_ctx_init(ctx));
}

void HwmonTest::showVersion(){
	restoreCtx();
	ctx->user_options->version = true;
	CPPUNIT_ASSERT(!hwmon_ctx_init(ctx));
}

void HwmonTest::showUsage(){
	restoreCtx();
	ctx->user_options->usage = true;
	CPPUNIT_ASSERT(!hwmon_ctx_init(ctx));
}

void HwmonTest::stdout(){
	restoreCtx();
	ctx->user_options->stdout_flag = true;
	CPPUNIT_ASSERT(!hwmon_ctx_init(ctx));
}

void HwmonTest::exampleHashes(){
	restoreCtx();
	ctx->user_options->example_hashes = true;
	CPPUNIT_ASSERT(!hwmon_ctx_init(ctx));
}
