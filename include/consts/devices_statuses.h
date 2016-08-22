#pragma once
/**
* status
*/
typedef enum DEVICES_STATUS_ {
  STATUS_STARTING = 0,
  STATUS_INIT = 1,
  STATUS_RUNNING = 2,
  STATUS_PAUSED = 3,
  STATUS_EXHAUSTED = 4,
  STATUS_CRACKED = 5,
  STATUS_ABORTED = 6,
  STATUS_QUIT = 7,
  STATUS_BYPASS = 8,
  STATUS_STOP_AT_CHECKPOINT = 9,
  STATUS_AUTOTUNE = 10
} DEVICES_STATUS;

static const char ST_0000[] = "Initializing";
static const char ST_0001[] = "Starting";
static const char ST_0002[] = "Running";
static const char ST_0003[] = "Paused";
static const char ST_0004[] = "Exhausted";
static const char ST_0005[] = "Cracked";
static const char ST_0006[] = "Aborted";
static const char ST_0007[] = "Quit";
static const char ST_0008[] = "Bypass";
static const char ST_0009[] = "Running (stop at checkpoint)";
static const char ST_0010[] = "Autotuning";
