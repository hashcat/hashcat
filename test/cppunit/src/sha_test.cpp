#include <cppunit/TestCase.h>
#include <cppunit/TestCaller.h>

#include "sha_test.h"

extern "C" {
	#include "modules/module_01400.c";
}


using std::cout;
using std::string;

void ShaTest::tryCall(){
    char x[65] = "hashcat";
    module_hash_encode(x);
    cout <<"\n" << x << "\n";


}

CppUnit::Test *ShaTest::suite(){
	CppUnit::TestSuite* suite = new CppUnit::TestSuite("Hwmon Test");
	suite->addTest(new CppUnit::TestCaller<ShaTest>("TryCall", &ShaTest::tryCall));
	return suite;
}
