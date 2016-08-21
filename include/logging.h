#pragma once
#include "common.h"
int log_final(FILE * fp, const char * fmt, va_list ap);

int log_out_nn(FILE *fp, const char *fmt, ...);
int log_info_nn(const char *fmt, ...);
int log_error_nn(const char *fmt, ...);

int log_out(FILE *fp, const char *fmt, ...);
int log_info(const char *fmt, ...);
int log_error(const char *fmt, ...);
