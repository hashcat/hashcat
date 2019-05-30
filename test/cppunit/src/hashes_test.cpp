#include <iostream>
#include <stdio.h>

#include <cppunit/TestFixture.h>
#include <cppunit/TestCase.h>
#include <cppunit/TestCaller.h>
#include <cppunit/TestSuite.h>

#include "hashes_test.h"

extern "C" {
    #include "memory.h"
    #include "hashes.h"
    #include "hashcat.h"
}

void HashesTest::setUp() {
    ctx = (hashcat_ctx_t *) hcmalloc(sizeof(hashcat_ctx_t));
    hashcat_init(ctx, NULL);
    ctx->hashconfig->is_salted = false;
    ctx->hashconfig->dgst_pos0 = 3;
    ctx->hashconfig->dgst_pos1 = 2;
    ctx->hashconfig->dgst_pos2 = 1;
    ctx->hashconfig->dgst_pos3 = 0;
    ctx->hashconfig->dgst_size = (4 * sizeof(u32));
    ctx->hashconfig->potfile_keep_all_hashes = false;
    ctx->hashconfig->esalt_size = 0;
    ctx->hashconfig->hook_salt_size = 0;
    ctx->hashconfig->opts_type = 0;
    ctx->hashes->hashes_cnt = 0;
    ctx->hashes->salts_cnt = 0;
    ctx->user_options->username = false;
    ctx->user_options->quiet = true;
}

void HashesTest::tearDown() {
    hashcat_destroy(ctx);
    free(ctx);
}

void HashesTest::setDefaultCtx(int hash_count) {
    hash_t *hashes_buf = (hash_t *) hcmalloc(hash_count * sizeof(hash_t));

    for (int i = 0; i < hash_count; i++) {

        // Initialize default salts if salted
        hashes_buf[i].salt = (salt_t *) hcmalloc(sizeof(salt_t));
        salt_t *salt = hashes_buf[i].salt;
        for (int j = 0; j < 64; j++) {
            salt->salt_buf[j] = 0;
            salt->salt_buf_pc[j] = 0;
        }
        salt->salt_len = 10;
        salt->salt_iter = 10;

        // Initialize default digests
        hashes_buf[i].digest = (void *) hcmalloc(4 * sizeof(u32));
        for (int j = 0; j < 4; j++) {
            u32* digest = (u32 *) hashes_buf[i].digest;
            digest[j] = 0;
        }
    }

    ctx->hashes->hashes_buf = hashes_buf;
    ctx->hashes->hashes_cnt = hash_count;
}

void HashesTest::setHash(int pos, u32 *digest) {
    u32 *d = (u32 *) ctx->hashes->hashes_buf[pos].digest;
    for (int i = 0; i < 4; i++) {
        d[i] = digest[i];
    }
}

CppUnit::Test *HashesTest::suite(){
    CppUnit::TestSuite* suite = new CppUnit::TestSuite("Hashes Test");
    suite->addTest(new CppUnit::TestCaller<HashesTest>("testRemoveDuplicates", 
                &HashesTest::testRemoveDuplicates));
    suite->addTest(new CppUnit::TestCaller<HashesTest>("testKeepAllHashes", 
                &HashesTest::testKeepAllHashes));
    suite->addTest(new CppUnit::TestCaller<HashesTest>("testRemoveDuplicatesWithSalt", 
                &HashesTest::testRemoveDuplicatesWithSalt));
    suite->addTest(new CppUnit::TestCaller<HashesTest>("testKeepAllHashesWithSalt", 
                &HashesTest::testKeepAllHashesWithSalt));
    suite->addTest(new CppUnit::TestCaller<HashesTest>("testUsernameOption", 
                &HashesTest::testUsernameOption));
    return suite;
}

void HashesTest::testRemoveDuplicates() {
    printf("\n\nHashesTest Suite\n\n");
    printf("Running testRemoveDuplicates\n");
    setDefaultCtx(8);

    // Set Hash list
    setHash(0, (u32 []) {0, 0, 0, 0});
    setHash(1, (u32 []) {1, 0, 5, 0});
    setHash(2, (u32 []) {1, 0, 5, 0});
    setHash(3, (u32 []) {5, 1, 2, 0});
    setHash(4, (u32 []) {5, 1, 3, 0});
    setHash(5, (u32 []) {6, 8, 2, 1});
    setHash(6, (u32 []) {10, 10, 10, 10});
    setHash(7, (u32 []) {10, 10, 10, 10});

    CPPUNIT_ASSERT(hashes_init_stage2(ctx) == 0);

    // Verify that 2 hashes were removed
    CPPUNIT_ASSERT(ctx->hashes->hashes_cnt == 6);

    // Verify that the hash in index 2 is now the one that was originally in 3
    CPPUNIT_ASSERT(((u32 *) ctx->hashes->hashes_buf[2].digest)[2] == 2);

    // Verify that the hash at index 5 is the one that was originally index 7
    CPPUNIT_ASSERT(((u32 *) ctx->hashes->hashes_buf[5].digest)[1] == 10);

}

void HashesTest::testKeepAllHashes() {
    printf("Running testKeepAllHashes\n");
    setDefaultCtx(8);
    ctx->hashconfig->potfile_keep_all_hashes = true;

    // Set Hash list
    setHash(0, (u32 []) {0, 0, 0, 0});
    setHash(1, (u32 []) {1, 0, 5, 0});
    setHash(2, (u32 []) {1, 0, 5, 0});
    setHash(3, (u32 []) {5, 1, 2, 0});
    setHash(4, (u32 []) {5, 1, 3, 0});
    setHash(5, (u32 []) {6, 8, 2, 1});
    setHash(6, (u32 []) {10, 10, 10, 10});
    setHash(7, (u32 []) {10, 10, 10, 10});

    CPPUNIT_ASSERT(hashes_init_stage2(ctx) == 0);
    CPPUNIT_ASSERT(ctx->hashes->hashes_cnt == 8);

}

void HashesTest::testRemoveDuplicatesWithSalt() {
    printf("Running testRemoveDuplicatesWithSalt\n");
    setDefaultCtx(8);
    ctx->hashconfig->is_salted = true;

    // Set Hash list
    setHash(0, (u32 []) {1, 0, 0, 0});
    setHash(1, (u32 []) {1, 0, 0, 0});
    setHash(2, (u32 []) {1, 0, 0, 0});
    setHash(3, (u32 []) {1, 0, 0, 0});
    setHash(4, (u32 []) {2, 0, 3, 0});
    setHash(5, (u32 []) {1, 0, 0, 0});
    setHash(6, (u32 []) {10, 0, 0, 35});
    setHash(7, (u32 []) {10, 0, 0, 35});

    // Set Salts
    ctx->hashes->hashes_buf[0].salt->salt_len = 10;
    ctx->hashes->hashes_buf[1].salt->salt_len = 11;
    ctx->hashes->hashes_buf[2].salt->salt_len = 15;
    ctx->hashes->hashes_buf[3].salt->salt_len = 15;
    ctx->hashes->hashes_buf[4].salt->salt_len = 15;
    ctx->hashes->hashes_buf[5].salt->salt_len = 30;
    ctx->hashes->hashes_buf[6].salt->salt_len = 40;
    ctx->hashes->hashes_buf[7].salt->salt_len = 40;

    // Two hashes should be removed: Hashes with indexes 3 and 7.
    // These are the only ones who match another hash by both salt and digest
    // exactly.

    CPPUNIT_ASSERT(hashes_init_stage2(ctx) == 0);
    CPPUNIT_ASSERT(ctx->hashes->hashes_cnt == 6);

    // Verify that there are 5 unique salts
    CPPUNIT_ASSERT(ctx->hashes->salts_cnt == 5);

    // Verify that the hash at index 3 is now the hash that was at index 4
    CPPUNIT_ASSERT(((u32 *) ctx->hashes->hashes_buf[3].digest)[2] == 3);
    CPPUNIT_ASSERT(ctx->hashes->hashes_buf[3].salt->salt_len == 15);

}

void HashesTest::testKeepAllHashesWithSalt() {
    printf("Running testKeepAllHashesWithSalt\n");
    setDefaultCtx(8);
    ctx->hashconfig->is_salted = true;
    ctx->hashconfig->potfile_keep_all_hashes = true;

    // Set Hash list
    setHash(0, (u32 []) {1, 0, 0, 0});
    setHash(1, (u32 []) {1, 0, 0, 0});
    setHash(2, (u32 []) {1, 0, 0, 0});
    setHash(3, (u32 []) {1, 0, 0, 0});
    setHash(4, (u32 []) {2, 0, 3, 0});
    setHash(5, (u32 []) {1, 0, 0, 0});
    setHash(6, (u32 []) {10, 0, 0, 35});
    setHash(7, (u32 []) {10, 0, 0, 35});

    // Set Salts
    ctx->hashes->hashes_buf[0].salt->salt_len = 10;
    ctx->hashes->hashes_buf[1].salt->salt_len = 11;
    ctx->hashes->hashes_buf[2].salt->salt_len = 15;
    ctx->hashes->hashes_buf[3].salt->salt_len = 15;
    ctx->hashes->hashes_buf[4].salt->salt_len = 15;
    ctx->hashes->hashes_buf[5].salt->salt_len = 30;
    ctx->hashes->hashes_buf[6].salt->salt_len = 40;
    ctx->hashes->hashes_buf[7].salt->salt_len = 40;

    // Two hashes should be removed: Hashes with indexes 3 and 7.
    // These are the only ones who match another hash by both salt and digest
    // exactly.

    CPPUNIT_ASSERT(hashes_init_stage2(ctx) == 0);
    CPPUNIT_ASSERT(ctx->hashes->hashes_cnt == 8);

    // Verify that there are 5 unique salts
    CPPUNIT_ASSERT(ctx->hashes->salts_cnt == 5);

    // Verify that the hash at index 4 is in the same spot
    CPPUNIT_ASSERT(((u32 *) ctx->hashes->hashes_buf[4].digest)[2] == 3);
    CPPUNIT_ASSERT(ctx->hashes->hashes_buf[4].salt->salt_len == 15);

}

void HashesTest::testUsernameOption() {
    printf("Running testUsernameOption\n");
    setDefaultCtx(8);

    // Set username option and set keep all hashes for ease
    ctx->user_options->username = true;
    ctx->hashconfig->potfile_keep_all_hashes = true;

    // Set Hash list
    setHash(0, (u32 []) {0, 0, 0, 0});
    setHash(1, (u32 []) {1, 0, 5, 0});
    setHash(2, (u32 []) {1, 0, 5, 0});
    setHash(3, (u32 []) {5, 1, 2, 0});
    setHash(4, (u32 []) {5, 1, 3, 0});
    setHash(5, (u32 []) {6, 8, 2, 1});
    setHash(6, (u32 []) {10, 10, 10, 10});
    setHash(7, (u32 []) {10, 10, 10, 10});

    // Set all hash_info for all hashes to NULL except for hash 5
    for (int i = 0; i < 8; i++) {
        ctx->hashes->hashes_buf[i].hash_info = NULL;
    }

    ctx->hashes->hashes_buf[5].hash_info = (hashinfo_t *) hcmalloc(sizeof(hashinfo_t));
    ctx->hashes->hashes_buf[5].hash_info->orighash = (char *) hcmalloc(10 * sizeof(char));
    strcpy(ctx->hashes->hashes_buf[5].hash_info->orighash, "VerifyStr");

    CPPUNIT_ASSERT(hashes_init_stage2(ctx) == 0);

    // Verify that Hash info was copied over and set
    CPPUNIT_ASSERT(strcmp("VerifyStr", ctx->hashes->hash_info[5]->orighash) == 0);

    free(ctx->hashes->hashes_buf[5].hash_info->orighash);
    free(ctx->hashes->hashes_buf[5].hash_info);
}

