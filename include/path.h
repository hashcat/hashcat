/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PATH_H
#define HC_PATH_H

HC_PLUGIN_API char *filename_from_filepath (char *filepath);

HC_PLUGIN_API bool hc_path_is_file (const char *path);
HC_PLUGIN_API bool hc_path_is_directory (const char *path);
HC_PLUGIN_API bool hc_path_is_fifo (const char *path);
HC_PLUGIN_API bool hc_path_is_empty (const char *path);
HC_PLUGIN_API bool hc_path_exist (const char *path);
HC_PLUGIN_API bool hc_path_read (const char *path);
HC_PLUGIN_API bool hc_path_write (const char *path);
HC_PLUGIN_API bool hc_path_create (const char *path);

HC_PLUGIN_API bool check_file_suffix (const char *file, const char *suffix);
HC_PLUGIN_API bool remove_file_suffix (char *file, const char *suffix);

#endif // HC_PATH_H
