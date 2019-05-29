#include "convert_test.h"

#include <cppunit/TestCase.h>
#include <cppunit/TestCaller.h>

extern "C" {
    #include "convert.h"
}

CppUnit::TestSuite *ConvertTest::suite(){
    CppUnit::TestSuite* suite = new CppUnit::TestSuite("Hwmon Test");
	suite->addTest(new CppUnit::TestCaller<ConvertTest>("isValidBase64Valid", &ConvertTest::isValidBase64Valid));
    suite->addTest(new CppUnit::TestCaller<ConvertTest>("isValidBase64ValidPadding", &ConvertTest::isValidBase64ValidPadding));
    suite->addTest(new CppUnit::TestCaller<ConvertTest>("isValidBase64InvalidChars", &ConvertTest::isValidBase64InvalidChars));
    suite->addTest(new CppUnit::TestCaller<ConvertTest>("isValidBase64InvalidLength", &ConvertTest::isValidBase64InvalidLength));
    suite->addTest(new CppUnit::TestCaller<ConvertTest>("isValidBase64InvalidPadding", &ConvertTest::isValidBase64InvalidPadding));
    suite->addTest(new CppUnit::TestCaller<ConvertTest>("isValidBase64InvalidEmpty", &ConvertTest::isValidBase64InvalidEmpty));
    suite->addTest(new CppUnit::TestCaller<ConvertTest>("isValidBase64InvalidSingleChar", &ConvertTest::isValidBase64InvalidSingleChar));
	return suite;
}

/* convert.(c|h)::is_valid_base64(a|b|c)_string(const u8 *)
 *
 * Tests the validity checks of base64 strings which
 * are oftened used to store hashes and salts, depending
 * on the algorithm.
 *
 */

// Test with valid base64 string
void ConvertTest::isValidBase64Valid(){
    assertBase64Validity("ABCD1234", true);
}

// Test with valid base64 string using padding to meet multiple of 4 requirement
void ConvertTest::isValidBase64ValidPadding(){
    assertBase64Validity("ABCD12345===", true);
}

// Test with invalid character, Z
void ConvertTest::isValidBase64InvalidChars(){
    assertBase64Validity("ABCZ1234", false);
}

// Test with invalid length (not multiple of 4, so does not resolve to integer byte count)
void ConvertTest::isValidBase64InvalidLength(){
    assertBase64Validity("ABCD12345", false);
}

// Test with invalid, redundant padding
void ConvertTest::isValidBase64InvalidPadding(){
    assertBase64Validity("ABCD1234====", false);
}

// Test with invalid, empty string
void ConvertTest::isValidBase64InvalidEmpty(){
    assertBase64Validity("", false);
}

// Test with invalid, single character string, for a 1-iteration loop test
void ConvertTest::isValidBase64InvalidSingleChar(){
    assertBase64Validity("1", false);
}

/*
 * Helper function which asserts that hashcat's determined
 * validity of the base64 string matches the predetermined
 * actual validity using all three base64 validity check functions.
 */
void ConvertTest::assertBase64Validity(const char *s, bool valid){
    CPPUNIT_ASSERT(is_valid_base64a_string((const u8 *) s, strlen(s)) == valid);
    CPPUNIT_ASSERT(is_valid_base64b_string((const u8 *) s, strlen(s)) == valid);
    CPPUNIT_ASSERT(is_valid_base64c_string((const u8 *) s, strlen(s)) == valid);
}
