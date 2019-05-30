#include <cppunit/TestCase.h>
#include <cppunit/TestCaller.h>

#include "hwmon_test.h"

extern "C" {
	#include "hwmon.h"
	#include "memory.h"
	#include "dynloader.h"
}

using std::cout;
using std::string;

void HwmonTest::setUp(){
	initCtx();
}

void HwmonTest::tearDown(){
	freeCtx();
}

void HwmonTest::initCtx(){
	ctx = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));
	ctx->hwmon_ctx = (hwmon_ctx_t *) hcmalloc(sizeof(hwmon_ctx_t));
	ctx->user_options = (user_options_t *) hcmalloc(sizeof(user_options_t));
	ctx->opencl_ctx = (opencl_ctx_t *) hcmalloc(sizeof(opencl_ctx_t));
}

void HwmonTest::freeCtx(){
	if(ctx == NULL) return;

	if(ctx->hwmon_ctx != NULL){
		free(ctx->hwmon_ctx);
		ctx->hwmon_ctx = NULL;
	}
	if(ctx->user_options != NULL){
		free(ctx->user_options);
		ctx->user_options = NULL;
	}
	if(ctx->opencl_ctx != NULL){
		free(ctx->opencl_ctx);
		ctx->opencl_ctx = NULL;
	}

	free(ctx->hwmon_ctx);
	ctx = NULL;
}

void HwmonTest::restoreCtx(){
	freeCtx();
	initCtx();
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

/* hwmon.(c|h)::hwmon_ctx_init(hashcat_ctx_t *)
 *
 * Tests the initialization of the hardware monitoring
 * context given various global hashcat contexts
 *
 */

// Test with disabled hwmon
void HwmonTest::disabledHwmon(){
	restoreCtx();
	ctx->user_options->hwmon_disable = true;
	CPPUNIT_ASSERT(!hwmon_ctx_init(ctx));
}

// Test with user option "show"
void HwmonTest::showVersion(){
	restoreCtx();
	ctx->user_options->version = true;
	CPPUNIT_ASSERT(!hwmon_ctx_init(ctx));
}

// Test with user option "show usage"
void HwmonTest::showUsage(){
	restoreCtx();
	ctx->user_options->usage = true;
	CPPUNIT_ASSERT(!hwmon_ctx_init(ctx));
}

// Test with user option "stdout_flag"
void HwmonTest::stdout(){
	restoreCtx();
	ctx->user_options->stdout_flag = true;
	CPPUNIT_ASSERT(!hwmon_ctx_init(ctx));
}

// Test with user option "example hashes"
void HwmonTest::exampleHashes(){
	restoreCtx();
	ctx->user_options->example_hashes = true;
	CPPUNIT_ASSERT(!hwmon_ctx_init(ctx));
}
