#include <cppunit/TestCase.h>
#include <cppunit/TestCaller.h>

#include "mode_test.h"

extern "C" {
    #include "folder.h"
    #include "memory.h"
    #include "shared.h"
    #include "thread.h"
    #include "timer.h"
    #include "common.h"
    #include "event.h"
    #include "opencl.h"
    #include "modules.h"
    #include "dynloader.h"
    #include "interface.h"


    #include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "user_options.h"
#include "usage.h"
#include "hashcat.h"
#include "terminal.h"
#include "status.h"

}


using std::cout;
using std::string;

void ModeTest::testGood1(){
  ctx = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));
  const int rc_hashcat_init = hashcat_init (ctx, NULL);

  CPPUNIT_ASSERT(!(rc_hashcat_init == -1));

  const int rc_options_init = user_options_init (ctx);
  CPPUNIT_ASSERT(!(rc_options_init == -1) );

  ctx->folder_config->shared_dir = "/home/therek/Documents/hashcat";

  ctx->user_options->attack_mode=0;
  ctx->user_options->hash_mode=1400;

  const int rc_hashconfig = hashconfig_init (ctx);
  CPPUNIT_ASSERT(!(rc_hashconfig == -1));


  free(ctx);
  return;
}

void ModeTest::testGood2(){
  ctx = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));
  const int rc_hashcat_init = hashcat_init (ctx, NULL);

  CPPUNIT_ASSERT(!(rc_hashcat_init == -1));

  const int rc_options_init = user_options_init (ctx);
  CPPUNIT_ASSERT(!(rc_options_init == -1) );

  ctx->folder_config->shared_dir = "/home/therek/Documents/hashcat";

  ctx->user_options->attack_mode=0;
  ctx->user_options->hash_mode=10;

  const int rc_hashconfig = hashconfig_init (ctx);
  CPPUNIT_ASSERT(!(rc_hashconfig == -1));


  free(ctx);
  return;
}

void ModeTest::testGood3(){
  ctx = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));
  const int rc_hashcat_init = hashcat_init (ctx, NULL);

  CPPUNIT_ASSERT(!(rc_hashcat_init == -1));

  const int rc_options_init = user_options_init (ctx);
  CPPUNIT_ASSERT(!(rc_options_init == -1) );

  ctx->folder_config->shared_dir = "/home/therek/Documents/hashcat";

  ctx->user_options->attack_mode=0;
  ctx->user_options->hash_mode=13733;

  const int rc_hashconfig = hashconfig_init (ctx);
  CPPUNIT_ASSERT(!(rc_hashconfig == -1));


  free(ctx);
  return;
}

void ModeTest::testBad1(){
  ctx = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));
  const int rc_hashcat_init = hashcat_init (ctx, NULL);

  CPPUNIT_ASSERT(!(rc_hashcat_init == -1));

  const int rc_options_init = user_options_init (ctx);
  CPPUNIT_ASSERT(!(rc_options_init == -1) );

  ctx->folder_config->shared_dir = NULL;

  ctx->user_options->attack_mode=0;
  ctx->user_options->hash_mode=1400;

  const int rc_hashconfig = hashconfig_init (ctx);
  CPPUNIT_ASSERT(!(rc_hashconfig == -1));


  free(ctx);
  return;
}

void ModeTest::testBad2(){
  ctx = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));
  const int rc_hashcat_init = hashcat_init (ctx, NULL);

  CPPUNIT_ASSERT(!(rc_hashcat_init == -1));

  const int rc_options_init = user_options_init (ctx);
  CPPUNIT_ASSERT(!(rc_options_init == -1) );

  ctx->folder_config->shared_dir = "/home/therek/Documents/hashcat";

  ctx->user_options->attack_mode=0;
  ctx->user_options->hash_mode=654;

  const int rc_hashconfig = hashconfig_init (ctx);
  CPPUNIT_ASSERT(!(rc_hashconfig == -1));


  free(ctx);
  return;
}

CppUnit::Test *ModeTest::suite(){
  printf("\n\n\nEntering mode select suite\n");
	CppUnit::TestSuite* suite = new CppUnit::TestSuite("Mode Selection Test");
	
  //good
  printf("running testgood: 1\n");
  suite->addTest(new CppUnit::TestCaller<ModeTest>("testGood1", &ModeTest::testGood1));
  printf("running testgood: 2\n");
  suite->addTest(new CppUnit::TestCaller<ModeTest>("testGood2", &ModeTest::testGood2));
  printf("running testgood: 3\n");
	suite->addTest(new CppUnit::TestCaller<ModeTest>("testGood3", &ModeTest::testGood3));

  //bad
  printf("running testbad: 1\n");
	suite->addTest(new CppUnit::TestCaller<ModeTest>("testBad1", &ModeTest::testBad1));
	
  printf("running testbad: 2\n");
  suite->addTest(new CppUnit::TestCaller<ModeTest>("testBad2", &ModeTest::testBad2));

	return suite;
}
