#ifndef Mode_TEST_H
#define Mode_TEST_H

#include <cppunit/TestFixture.h>
#include <cppunit/TestSuite.h>

extern "C" {
	#ifndef _TYPES_H
	    #include "types.h"
	#endif
}

class ModeTest : public CppUnit::TestFixture{
    private:
        hashcat_ctx_t * ctx;
        
    public:
        void testGood1();
        void testGood2();
        void testGood3();
        void testBad1();
        void testBad2();

        static CppUnit::Test *suite();


};
#endif