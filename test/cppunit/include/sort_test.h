#ifndef SORT_TEST_H
#define SORT_TEST_H

#include <iostream>

#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>

extern "C" {
    #ifndef _TYPES_H
    #include "types.h"
    #endif
}

class SortTest : public CppUnit::TestFixture{
private:
    hashcat_ctx_t *ctx;
    void setDefaultCtx();
public:
    void setUp();
    void tearDown();
    static CppUnit::Test *suite();

    void testEqualDigest();
    void testGreaterThanDigest1();
    void testGreaterThanDigest2();
    void testGreaterThanDigest3();
    void testGreaterThanDigest4();
    void testLessThanDigest1();
    void testLessThanDigest2();
    void testLessThanDigest3();
    void testLessThanDigest4();
    void testNullDigest1();
    void testNullDigest2();
    //void stdout();
};

#endif
