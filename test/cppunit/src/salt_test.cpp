#include <iostream>

#include <cppunit/TestFixture.h>
#include <cppunit/TestCase.h>
#include <cppunit/TestCaller.h>
#include <cppunit/TestSuite.h>

#include "salt_test.h"

extern "C" {
    #include "memory.h"
    #include "hashes.h"
}

void SaltTest::setUp() {
    s1 = (salt_t *) hcmalloc(sizeof(salt_t));
    s2 = (salt_t *) hcmalloc(sizeof(salt_t));
}

void SaltTest::tearDown() {
    free(s1);
    free(s2);
}

void SaltTest::setDefaultSalt() {
    for (int i = 0; i < 64; i++) {
        s1->salt_buf[i] = 0;
        s2->salt_buf[i] = 0;
        s1->salt_buf_pc[i] = 0;
        s2->salt_buf_pc[i] = 0;
    }

    s1->salt_len = 10;
    s2->salt_len = 10;

    s1->salt_iter = 10;
    s2->salt_iter = 10;
}

CppUnit::Test *SaltTest::suite(){
    CppUnit::TestSuite* suite = new CppUnit::TestSuite("Salt Test");
    suite->addTest(new CppUnit::TestCaller<SaltTest>("testEqualSalt", 
                &SaltTest::testEqualSalt));
    suite->addTest(new CppUnit::TestCaller<SaltTest>("testLongSalt", 
                &SaltTest::testLongSalt));
    suite->addTest(new CppUnit::TestCaller<SaltTest>("testShortSalt", 
                &SaltTest::testShortSalt));
    suite->addTest(new CppUnit::TestCaller<SaltTest>("testSaltIter", 
                &SaltTest::testSaltIter));
    suite->addTest(new CppUnit::TestCaller<SaltTest>("testSaltBufGreaterThan", 
                &SaltTest::testSaltBufGreaterThan));
    suite->addTest(new CppUnit::TestCaller<SaltTest>("testSaltBufLessThan", 
                &SaltTest::testSaltBufLessThan));
    suite->addTest(new CppUnit::TestCaller<SaltTest>("testSaltBufPcGreaterThan", 
                &SaltTest::testSaltBufPcGreaterThan));
    suite->addTest(new CppUnit::TestCaller<SaltTest>("testSaltBufPcLessThan", 
                &SaltTest::testSaltBufPcLessThan));
    /*suite->addTest(new CppUnit::TestCaller<SaltTest>("testNullSalt1", 
                &SaltTest::testNullSalt1));
    suite->addTest(new CppUnit::TestCaller<SaltTest>("testNullSalt2", 
                &SaltTest::testNullSalt2));*/
    return suite;
}

void SaltTest::testEqualSalt() {
    printf("\n\nSaltTest Suite\n\n");
    printf("Running testEqualSalt\n");
    setDefaultSalt();
    CPPUNIT_ASSERT(sort_by_salt(s1, s2) == 0);
}

void SaltTest::testLongSalt() {
    printf("Running testLongSalt\n");
    setDefaultSalt();

    // Construct salts so that s1 is a longer length, but has a lower iteration
    // and the values in the salt buffer are lower
    s1->salt_len = 10;
    s2->salt_len = 5;
    s1->salt_iter = 15;
    s2->salt_iter = 20;
    for (int i = 0; i < 64; i++) {
        s2->salt_buf[i] = 15;
        s2->salt_buf_pc[i] = 15;
    }

    CPPUNIT_ASSERT(sort_by_salt(s1, s2) > 0);
}

void SaltTest::testShortSalt() {
    printf("Running testShortSalt\n");
    setDefaultSalt();

    // Construct salts so that s2 is a longer length, but has a lower iteration
    // and the values in the salt buffer are lower
    s2->salt_len = 10;
    s1->salt_len = 5;
    s2->salt_iter = 15;
    s1->salt_iter = 20;
    for (int i = 0; i < 64; i++) {
        s1->salt_buf[i] = 15;
        s1->salt_buf_pc[i] = 15;
    }

    CPPUNIT_ASSERT(sort_by_salt(s1, s2) < 0);
}

void SaltTest::testSaltIter() {
    printf("Running testSaltIter\n");
    setDefaultSalt();

    // Construct salts so that s1 has a larger iteration, but values in the salt
    // buffer are lower than s2
    s1->salt_iter = 20;
    s2->salt_iter = 5;
    for (int i = 0; i < 64; i++) {
        s2->salt_buf[i] = 15;
        s2->salt_buf_pc[i] = 15;
    }

    CPPUNIT_ASSERT(sort_by_salt(s1, s2) > 0);
}

void SaltTest::testSaltBufGreaterThan() {
    printf("Running testSaltBufGreaterThan\n");
    setDefaultSalt();

    s1->salt_buf[5] = 20;
    s2->salt_buf[15] = 40;
    s2->salt_buf[50] = 60;
    s2->salt_buf_pc[0] = 100;

    CPPUNIT_ASSERT(sort_by_salt(s1, s2) > 0);
}

void SaltTest::testSaltBufLessThan() {
    printf("Running testSaltBufLessThan\n");
    setDefaultSalt();

    s2->salt_buf[5] = 20;
    s1->salt_buf[15] = 40;
    s1->salt_buf[50] = 60;
    s1->salt_buf_pc[0] = 100;

    CPPUNIT_ASSERT(sort_by_salt(s1, s2) < 0);
}

void SaltTest::testSaltBufPcGreaterThan() {
    printf("Running testSaltBufPcGreaterThan\n");
    setDefaultSalt();

    s1->salt_buf_pc[5] = 20;
    s2->salt_buf_pc[15] = 40;
    s2->salt_buf_pc[50] = 60;

    CPPUNIT_ASSERT(sort_by_salt(s1, s2) > 0);
}

void SaltTest::testSaltBufPcLessThan() {
    printf("Running testSaltBufPcLessThan\n");
    setDefaultSalt();

    s2->salt_buf_pc[5] = 20;
    s1->salt_buf_pc[15] = 40;
    s1->salt_buf_pc[50] = 60;

    CPPUNIT_ASSERT(sort_by_salt(s1, s2) < 0);
}

void SaltTest::testNullSalt1() {
    printf("Running testNullSalt1\n");
    setDefaultSalt();

    CPPUNIT_ASSERT_THROW(sort_by_salt(NULL, s2), std::invalid_argument);
}

void SaltTest::testNullSalt2() {
    printf("Running testNullSalt2\n");
    setDefaultSalt();

    CPPUNIT_ASSERT_THROW(sort_by_salt(s1, NULL), std::invalid_argument);
}

