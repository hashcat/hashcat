#ifndef SHA_TEST_H
#define SHA_TEST_H

#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>

extern "C" {
	#ifndef _TYPES_H
	#include "types.h"
	#endif
}

class ShaTest : public CppUnit::TestFixture{
    private:
        
    public:
        void tryCall();
        static CppUnit::Test *suite();
}
#endif