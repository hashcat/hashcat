/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_SYSTEM_H
#define HC_SYSTEM_H

void setup_environment_variables (const folder_config_t *folder_config, const user_options_t *user_options);
void setup_umask (void);
void setup_seeding (const bool rp_gen_seed_chgd, const u32 rp_gen_seed);

HC_PLUGIN_API u32 get_random_num (const u32 min, const u32 max);

HC_PLUGIN_API int hc_get_processor_count (void);

HC_PLUGIN_API int select_read_timeout  (int sockfd, const int sec);
HC_PLUGIN_API int select_write_timeout (int sockfd, const int sec);

HC_PLUGIN_API int select_read_timeout_console (const int sec);

HC_PLUGIN_API int get_current_arch ();

#if defined (__APPLE__)
HC_PLUGIN_API bool is_apple_silicon (void);
#endif

HC_PLUGIN_API int  suppress_stderr (void);
HC_PLUGIN_API void restore_stderr (int saved_fd);

HC_API bool get_free_memory (u64 *free_mem);

#endif // HC_SYSTEM_H
