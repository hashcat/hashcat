#include <iostream>

#include <cppunit/TestFixture.h>
#include <cppunit/TestCase.h>
#include <cppunit/TestCaller.h>
#include <cppunit/TestSuite.h>

#include "sort_test.h"

extern "C" {
    #include "memory.h"
    #include "hashes.h"
}

void SortTest::setUp() {
    ctx = (hashcat_ctx_t *) hcmalloc(sizeof(hashcat_ctx_t));
    ctx->hashconfig = (hashconfig_t *) hcmalloc(sizeof(hashconfig_t));
}

void SortTest::tearDown() {
    free(ctx->hashconfig);
    free(ctx);
}

void SortTest::setDefaultCtx() {
    hashconfig_t *hashconfig = ctx->hashconfig;
    hashconfig->dgst_pos0 = 3;
    hashconfig->dgst_pos1 = 2;
    hashconfig->dgst_pos2 = 1;
    hashconfig->dgst_pos3 = 0;
}

CppUnit::Test *SortTest::suite(){
    CppUnit::TestSuite* suite = new CppUnit::TestSuite("Sort Test");
    suite->addTest(new CppUnit::TestCaller<SortTest>("testEqualDigest", 
                &SortTest::testEqualDigest));
    suite->addTest(new CppUnit::TestCaller<SortTest>("testGreaterThanDigest1", 
                &SortTest::testGreaterThanDigest1));
    suite->addTest(new CppUnit::TestCaller<SortTest>("testGreaterThanDigest2", 
                &SortTest::testGreaterThanDigest2));
    suite->addTest(new CppUnit::TestCaller<SortTest>("testGreaterThanDigest3", 
                &SortTest::testGreaterThanDigest3));
    suite->addTest(new CppUnit::TestCaller<SortTest>("testGreaterThanDigest4", 
                &SortTest::testGreaterThanDigest4));
    suite->addTest(new CppUnit::TestCaller<SortTest>("testLessThanDigest1", 
                &SortTest::testLessThanDigest1));
    suite->addTest(new CppUnit::TestCaller<SortTest>("testLessThanDigest2", 
                &SortTest::testLessThanDigest2));
    suite->addTest(new CppUnit::TestCaller<SortTest>("testLessThanDigest3", 
                &SortTest::testLessThanDigest3));
    suite->addTest(new CppUnit::TestCaller<SortTest>("testLessThanDigest4", 
                &SortTest::testLessThanDigest4));
    /*suite->addTest(new CppUnit::TestCaller<SortTest>("testNullDigest1", 
                &SortTest::testNullDigest1));
    suite->addTest(new CppUnit::TestCaller<SortTest>("testNullDigest2", 
                &SortTest::testNullDigest2));*/
    return suite;
}

void SortTest::testEqualDigest() {
    printf("\n\nSortTest Suite\n\n");
    printf("Running testEqualDigest\n");
    setDefaultCtx();
    u32 d1[4] = { 512, 256, 128, 64 };
    u32 d2[4] = { 512, 256, 128, 64 };
    CPPUNIT_ASSERT(sort_by_digest_p0p1(d1, d2, ctx->hashconfig) == 0);
}

void SortTest::testGreaterThanDigest1() {
    printf("Running testGreaterThanDigest1\n");
    setDefaultCtx();
    u32 d1[4] = { 512, 256, 128, 64 };
    u32 d2[4] = { 512, 256, 128, 63 };
    CPPUNIT_ASSERT(sort_by_digest_p0p1(d1, d2, ctx->hashconfig) == 1);
}

void SortTest::testGreaterThanDigest2() {
    printf("Running testGreaterThanDigest2\n");
    setDefaultCtx();
    u32 d1[4] = { 512, 256, 128, 64 };
    u32 d2[4] = { 512, 256, 127, 1000 };
    CPPUNIT_ASSERT(sort_by_digest_p0p1(d1, d2, ctx->hashconfig) == 1);
}

void SortTest::testGreaterThanDigest3() {
    printf("Running testGreaterThanDigest3\n");
    setDefaultCtx();
    u32 d1[4] = { 512, 256, 128, 64 };
    u32 d2[4] = { 512, 255, 1200, 1000 };
    CPPUNIT_ASSERT(sort_by_digest_p0p1(d1, d2, ctx->hashconfig) == 1);
}

void SortTest::testGreaterThanDigest4() {
    printf("Running testGreaterThanDigest4\n");
    setDefaultCtx();
    u32 d1[4] = { 512, 256, 128, 64 };
    u32 d2[4] = { 511, 2560, 1280, 1000 };
    CPPUNIT_ASSERT(sort_by_digest_p0p1(d1, d2, ctx->hashconfig) == 1);
}

void SortTest::testLessThanDigest1() {
    printf("Running testLessThanDigest1\n");
    setDefaultCtx();
    u32 d1[4] = { 512, 256, 128, 63 };
    u32 d2[4] = { 512, 256, 128, 64 };
    CPPUNIT_ASSERT(sort_by_digest_p0p1(d1, d2, ctx->hashconfig) == -1);
}

void SortTest::testLessThanDigest2() {
    printf("Running testLessThanDigest2\n");
    setDefaultCtx();
    u32 d1[4] = { 512, 256, 127, 640 };
    u32 d2[4] = { 512, 256, 128, 64 };
    CPPUNIT_ASSERT(sort_by_digest_p0p1(d1, d2, ctx->hashconfig) == -1);
}

void SortTest::testLessThanDigest3() {
    printf("Running testLessThanDigest3\n");
    setDefaultCtx();
    u32 d1[4] = { 512, 255, 1280, 640 };
    u32 d2[4] = { 512, 256, 128, 64 };
    CPPUNIT_ASSERT(sort_by_digest_p0p1(d1, d2, ctx->hashconfig) == -1);
}

void SortTest::testLessThanDigest4() {
    printf("Running testLessThanDigest4\n");
    setDefaultCtx();
    u32 d1[4] = { 511, 2560, 1280, 640 };
    u32 d2[4] = { 512, 256, 128, 64 };
    CPPUNIT_ASSERT(sort_by_digest_p0p1(d1, d2, ctx->hashconfig) == -1);
}

void SortTest::testNullDigest1() {
    printf("Running testNullDigest1\n");
    setDefaultCtx();
    u32 *d1 = NULL;
    u32 d2[4] = { 512, 256, 128, 64 };
    CPPUNIT_ASSERT_THROW(sort_by_digest_p0p1(d1, d2, ctx->hashconfig), std::invalid_argument);
}

void SortTest::testNullDigest2() {
    printf("Running testNullDigest2\n");
    setDefaultCtx();
    u32 d1[4] = { 512, 256, 128, 64 };
    u32 *d2 = NULL;
    CPPUNIT_ASSERT_THROW(sort_by_digest_p0p1(d1, d2, ctx->hashconfig), std::invalid_argument);
}

