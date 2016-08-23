#pragma once
#include "config.h"
#include "common.h"
#include "hc_concurrency.h"
#include "hc_global_data_t.h"

/**
* valid project specific global stuff
*/
extern const uint  VERSION_BIN;
extern const uint  RESTORE_MIN;

extern const char *PROMPT;

extern int SUPPRESS_OUTPUT;

extern hc_thread_mutex_t mux_display;

extern hc_thread_mutex_t mux_adl;
extern hc_thread_mutex_t mux_counter;
extern hc_thread_mutex_t mux_dispatcher;
extern hc_thread_mutex_t mux_display;
extern hc_global_data_t data;
