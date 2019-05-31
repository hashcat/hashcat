#include <cppunit/TestCase.h>
#include <cppunit/TestCaller.h>

#include "sha_test.h"

extern "C" {
    #include "types.h"
    #include "folder.h"
    #include "memory.h"
    #include "shared.h"
    #include "thread.h"
    #include "timer.h"
    #include "common.h"
    #include "types.h"
    #include "memory.h"
    #include "event.h"
    #include "shared.h"
    #include "opencl.h"
    #include "modules.h"
    #include "dynloader.h"
    #include "interface.h"
}


using std::cout;
using std::string;

void ShaTest::tryCall(){
    
  ctx = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));

  const int rc_hashcat_init = hashcat_init (hashcat_ctx, event);

  if (rc_hashcat_init == -1) cout << "BAD\n\n";

  free(ctx);
  return;


}

CppUnit::Test *ShaTest::suite(){
	CppUnit::TestSuite* suite = new CppUnit::TestSuite("Hwmon Test");
	suite->addTest(new CppUnit::TestCaller<ShaTest>("TryCall", &ShaTest::tryCall));
	return suite;
}
