#ifndef SALT_TEST_H
#define SALT_TEST_H

#include <iostream>

#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>

extern "C" {
    #ifndef _TYPES_H
    #include "types.h"
    #endif
}

class SaltTest : public CppUnit::TestFixture{
private:
    salt_t *s1;
    salt_t *s2;
    void setDefaultSalt();
public:
    void setUp();
    void tearDown();
    static CppUnit::Test *suite();

    void testEqualSalt();
    void testLongSalt();
    void testShortSalt();
    void testSaltIter();
    void testSaltBufGreaterThan();
    void testSaltBufLessThan();
    void testSaltBufPcGreaterThan();
    void testSaltBufPcLessThan();
    void testNullSalt1();
    void testNullSalt2();
};

#endif
