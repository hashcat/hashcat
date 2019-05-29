#ifndef CONVERT_TEST_H
#define CONVERT_TEST_H

#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>

extern "C" {
    #ifndef _TYPES_H
    #include "types.h"
    #endif
}

/*
 *
 * Class:   ConvertTest
 * Desc:    Tests hashcat validity checks of base64 strings,
 *          often used to represent various types of hashes.
 *
 */
class ConvertTest : public CppUnit::TestFixture {
private:
    void isValidBase64Valid();
    void isValidBase64ValidPadding();
    void isValidBase64InvalidChars();
    void isValidBase64InvalidLength();
    void isValidBase64InvalidPadding();
    void isValidBase64InvalidEmpty();
    void assertBase64Validity(const char *s, bool valid);
public:
    static CppUnit::TestSuite *suite();
};

#endif
