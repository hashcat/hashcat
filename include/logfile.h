#pragma once
#include "common.h"
char *logfile_generate_topid();
char *logfile_generate_subid();
FILE * logfile_open(char * logfile);
void logfile_close(FILE * fp);
void logfile_append(const char *fmt, ...);

int logfile_generate_id();


#include "hc_global.h"

inline void logfile_top_msg(const char* msg) {
  logfile_append("%s\t%s", data.topid, msg);
}
inline void logfile_sub_msg(const char* msg) {
  logfile_append("%s\t%s\t%s", data.topid, data.subid, msg);
}
inline void logfile_top_var_uint64(const char* var, unsigned long long val) {
  logfile_append("%s\t%s\t%llu", data.topid, var, val);
}
inline void logfile_sub_var_uint64(const char* var, unsigned long long val) {
  logfile_append("%s\t%s\t%s\t%llu", data.topid, data.subid, var, val);
}
inline void logfile_top_var_uint(const char* var, unsigned int val) {
  logfile_append("%s\t%s\t%u", data.topid, var, val);
}
inline void logfile_sub_var_uint(const char* var, unsigned int val) {
  logfile_append("%s\t%s\t%s\t%u", data.topid, data.subid, var, val);
}
inline void logfile_top_var_char(const char* var, char  val) {
  logfile_append("%s\t%s\t%c", data.topid, var, val);
}
inline void logfile_sub_var_char(const char* var, char val) {
  logfile_append("%s\t%s\t%s\t%c", data.topid, data.subid, var, val);
}
inline void logfile_top_var_string(const char* var, const char* val) {
  if (val != NULL)
    logfile_append("%s\t%s\t%s", data.topid, var, val);
}
inline void logfile_sub_var_string(const char* var, const char* val) {
  if (val != NULL)
    logfile_append("%s\t%s\t%s\t%s", data.topid, data.subid, var, val);
}
