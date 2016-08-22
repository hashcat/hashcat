#pragma once
int sort_by_u32(const void *p1, const void *p2);
int sort_by_mtime(const void *p1, const void *p2);
int sort_by_cpu_rule(const void *p1, const void *p2);
int sort_by_kernel_rule(const void *p1, const void *p2);
int sort_by_stringptr(const void *p1, const void *p2);
int sort_by_dictstat(const void *s1, const void *s2);
int sort_by_bitmap(const void *s1, const void *s2);

int sort_by_pot(const void *v1, const void *v2);
int sort_by_hash(const void *v1, const void *v2);
int sort_by_hash_no_salt(const void *v1, const void *v2);
int sort_by_salt(const void *v1, const void *v2);
int sort_by_salt_buf(const void *v1, const void *v2);
int sort_by_hash_t_salt(const void *v1, const void *v2);
int sort_by_digest_4_2(const void *v1, const void *v2);
int sort_by_digest_4_4(const void *v1, const void *v2);
int sort_by_digest_4_5(const void *v1, const void *v2);
int sort_by_digest_4_6(const void *v1, const void *v2);
int sort_by_digest_4_8(const void *v1, const void *v2);
int sort_by_digest_4_16(const void *v1, const void *v2);
int sort_by_digest_4_32(const void *v1, const void *v2);
int sort_by_digest_4_64(const void *v1, const void *v2);
int sort_by_digest_8_8(const void *v1, const void *v2);
int sort_by_digest_8_16(const void *v1, const void *v2);
int sort_by_digest_8_25(const void *v1, const void *v2);
int sort_by_digest_p0p1(const void *v1, const void *v2);

int sort_by_tuning_db_alias(const void * v1, const void * v2);

int sort_by_tuning_db_entry(const void * v1, const void * v2);

// special version for hccap (last 2 uints should be skipped where the digest is located)
int sort_by_hash_t_salt_hccap(const void *v1, const void *v2);
