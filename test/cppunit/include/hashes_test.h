#ifndef HASHES_TEST_H
#define HASHES_TEST_H

#include <iostream>

#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>

extern "C" {
    #ifndef _TYPES_H
    #include "types.h"
    #endif
}

class HashesTest : public CppUnit::TestFixture{
private:
    hashcat_ctx_t *ctx;
    void setDefaultCtx(int hash_count);
    void setHash(int pos, u32 *digest);
public:
    void setUp();
    void tearDown();
    static CppUnit::Test *suite();

    void testRemoveDuplicates();
    void testKeepAllHashes();
    void testRemoveDuplicatesWithSalt();
    void testKeepAllHashesWithSalt();
    void testUsernameOption();
};

#endif
