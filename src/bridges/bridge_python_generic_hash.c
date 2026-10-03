/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "bridges.h"
#include "memory.h"
#include "shared.h"
#include "thread.h"
#include "cpu_features.h"
#include "system.h"

#if defined (_WIN)
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined (__APPLE__)
#include <crt_externs.h>
#endif

// Every unit is a separate Python process running Python/hcworker.py, so hashcat no longer loads a
// Python library at all. A process shares nothing with the next one, which is what lets the units
// scale with the CPU threads whatever the plugin imports, on a standard or a free-threaded build and
// on every operating system. Threads in one interpreter only scale while the plugin runs pure Python:
// an extension with shared state, such as hashlib's OpenSSL, serializes them again.
//
// The interpreter is whatever "python3" resolves to, so an activated virtual environment and the
// version pyenv selects both apply without anything set for hashcat. --bridge-parameter2 names
// another interpreter.

#if defined (_WIN)
#define DEFAULT_PYTHON "python"
#else
#define DEFAULT_PYTHON "python3"
#endif

#define WORKER_FILENAME  "Python/hcworker.py"
#define DEFAULT_PLUGIN   "Python/generic_hash.py"

// The largest batch one unit can be handed. backend_session_begin () derives kernel_accel_max from it
// and lowers that again where the candidate buffers would not fit the device, and autotune then settles
// at about seven tenths of it.
//
// Autotune does NOT measure the plugin to get there. It times whichever kernel the mode runs, and a
// BRIDGE_TYPE_LAUNCH_LOOP mode's loop kernel is empty, so the figure it settles on depends on this
// constant and on nothing else: measured on an i7-14700K it picks accel 6, 211 and 711 under ceilings
// of 8, 256 and 1024, and picks the same three whether a candidate costs one sha256 or ten thousand.
// Declaring BRIDGE_TYPE_REPLACE_LOOP instead would put the bridge itself under the timer.
//
// So this number is the batch size in practice, and there are two things to weigh. Throughput, on 28
// units with a plugin computing one sha256: 16 kH/s at a ceiling of 8, which is what the old bridges
// used, 477 kH/s at 256 and 611 kH/s here, with the curve flat from 1024 on. Against that, memory: the
// buffers cost sizeof (generic_io_tmp_t) per candidate per unit, about 8.4 KB, so 1024 is 8.6 MB a unit
// on the host and the same again on the device. A batch is also one round trip, so Ctrl-C waits for the
// candidates already sent.

#define WORKITEM_COUNT_MAX 1024

// the protocol of Python/hcworker.py

#define PROTOCOL_VERSION 2

// What a worker writes before its first frame. See worker_sync ().

#define WORKER_MAGIC "HCPY"

#define FRAME_HELLO  1
#define FRAME_ERROR  2
#define FRAME_RESULT 3
#define FRAME_READY  4
#define FRAME_INIT   10
#define FRAME_BATCH  11

#define PW_LEN_MAX  256
#define OUT_LEN_MAX 256
#define OUT_CNT_MAX 32

// How long a worker gets to notice its input closed before it is killed

#define WORKER_EXIT_MSEC 2000

// The largest frame the protocol can produce, which is a RESULT of WORKITEM_COUNT_MAX candidates each
// holding OUT_CNT_MAX values of OUT_LEN_MAX bytes, plus the length words. Anything larger did not come
// from a worker speaking this protocol, and reading it would block on bytes nobody is going to send.

#define FRAME_LEN_MAX (4 + (WORKITEM_COUNT_MAX * (4 + (OUT_CNT_MAX * (4 + OUT_LEN_MAX)))))

typedef struct
{
  // input

  u32 pw_buf[64];
  u32 pw_len;

  // output

  u32 out_buf[32][64];
  u32 out_len[32];
  u32 out_cnt;

} generic_io_tmp_t;

typedef struct
{
  #if defined (_WIN)
  HANDLE process;
  HANDLE to_worker;
  HANDLE from_worker;
  #else
  pid_t  pid;
  int    to_worker;
  int    from_worker;
  #endif

  bool   running;
  bool   killed;

} worker_t;

typedef struct
{
  char unit_info_buf[1024];

  worker_t worker;

  u8    *send_buf;
  size_t send_size;

  u8    *recv_buf;
  size_t recv_size;

} unit_t;

typedef struct
{
  unit_t *units_buf;
  int     units_cnt;

  char   *python;
  char   *worker_path;
  char   *plugin_path;

  char   *version;
  char   *st_hash;
  char   *st_pass;

  const char *bridge_parameter[4];

  // Every unit is sent the same INIT payload, and on a large hash list that payload is the salt and
  // esalt tables. Building it per unit held one copy per unit at once, which on 28 units and 20000
  // salts was over a gigabyte for bytes that are identical. It is built once, on whichever unit starts
  // first, and every unit writes from it.

  u8    *init_buf;
  size_t init_size;
  u32    init_len;

  #if !defined (_WIN)
  void (*sigpipe_saved) (int);
  #endif

  // Starting a worker creates pipes whose other ends must reach only that worker. Two units starting
  // at once could hand one worker the pipe of another, and the leaked write end would keep that pipe
  // open after its own worker is gone, so starts are serialized. It also guards the INIT payload above.

  hc_thread_mutex_t spawn_mutex;

} bridge_context_t;

static bool buf_reserve (u8 **buf, size_t *size, const size_t need)
{
  if (*size >= need) return true;

  size_t new_size = MAX (need, *size * 2);

  u8 *new_buf = (u8 *) hcrealloc (*buf, *size, new_size - *size);

  if (new_buf == NULL) return false;

  *buf  = new_buf;
  *size = new_size;

  return true;
}

#if defined (_WIN)

static bool worker_start (worker_t *worker, const char *python, const char *worker_path, const char *plugin_path)
{
  char *cmdline = NULL;

  hc_asprintf (&cmdline, "\"%s\" \"%s\" \"%s\"", python, worker_path, plugin_path);

  SECURITY_ATTRIBUTES sa;

  sa.nLength              = sizeof (sa);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle       = TRUE;

  HANDLE to_r   = NULL;
  HANDLE to_w   = NULL;
  HANDLE from_r = NULL;
  HANDLE from_w = NULL;

  bool ok = (CreatePipe (&to_r, &to_w, &sa, 0) == TRUE) && (CreatePipe (&from_r, &from_w, &sa, 0) == TRUE);

  if (ok == true)
  {
    SetHandleInformation (to_w,   HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation (from_r, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;

    memset (&si, 0, sizeof (si));

    si.cb         = sizeof (si);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdInput  = to_r;
    si.hStdOutput = from_w;
    si.hStdError  = GetStdHandle (STD_ERROR_HANDLE);

    PROCESS_INFORMATION pi;

    ok = (CreateProcessA (NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi) == TRUE);

    if (ok == true)
    {
      CloseHandle (pi.hThread);

      worker->process = pi.hProcess;
    }
  }

  if (to_r)   CloseHandle (to_r);
  if (from_w) CloseHandle (from_w);

  hcfree (cmdline);

  if (ok == false)
  {
    if (to_w)   CloseHandle (to_w);
    if (from_r) CloseHandle (from_r);

    return false;
  }

  worker->to_worker   = to_w;
  worker->from_worker = from_r;
  worker->running     = true;

  return true;
}

static bool worker_write (worker_t *worker, const void *buf, const size_t len)
{
  const u8 *ptr = (const u8 *) buf;

  size_t done = 0;

  while (done < len)
  {
    DWORD written = 0;

    if (WriteFile (worker->to_worker, ptr + done, (DWORD) MIN (len - done, 1u << 30), &written, NULL) == FALSE) return false;

    done += written;
  }

  return true;
}

static bool worker_read (worker_t *worker, void *buf, const size_t len)
{
  u8 *ptr = (u8 *) buf;

  size_t done = 0;

  while (done < len)
  {
    DWORD got = 0;

    if (ReadFile (worker->from_worker, ptr + done, (DWORD) MIN (len - done, 1u << 30), &got, NULL) == FALSE) return false;

    if (got == 0) return false;

    done += got;
  }

  return true;
}

static void worker_stop (worker_t *worker)
{
  if (worker->running == false) return;

  // Closing its input is the worker's signal to finish, and a worker between batches exits at once.
  // One interrupted in the middle of a batch has a candidate to finish first, and a plugin that never
  // returns would hold hashcat here for good, so the wait is bounded and what is left gets killed.

  CloseHandle (worker->to_worker);
  CloseHandle (worker->from_worker);

  if (WaitForSingleObject (worker->process, WORKER_EXIT_MSEC) != WAIT_OBJECT_0)
  {
    TerminateProcess (worker->process, 1);

    WaitForSingleObject (worker->process, INFINITE);

    worker->killed = true;
  }

  CloseHandle (worker->process);

  worker->running = false;
}

#else

static bool worker_start (worker_t *worker, const char *python, const char *worker_path, const char *plugin_path)
{
  #if defined (__APPLE__)
  char **envp = *_NSGetEnviron ();
  #else
  extern char **environ;

  char **envp = environ;
  #endif

  char *argv[4];

  argv[0] = (char *) python;
  argv[1] = (char *) worker_path;
  argv[2] = (char *) plugin_path;
  argv[3] = NULL;

  int to[2]   = { -1, -1 };
  int from[2] = { -1, -1 };

  if ((pipe (to) == -1) || (pipe (from) == -1))
  {
    const int err = errno;

    if (to[0]   != -1) close (to[0]);
    if (to[1]   != -1) close (to[1]);
    if (from[0] != -1) close (from[0]);
    if (from[1] != -1) close (from[1]);

    errno = err;

    return false;
  }

  // The worker gets copies on descriptors 0 and 1, which dup2 () creates without the flag. The
  // originals close at exec, so no other process started later holds an end of this pipe.

  fcntl (to[0],   F_SETFD, FD_CLOEXEC);
  fcntl (to[1],   F_SETFD, FD_CLOEXEC);
  fcntl (from[0], F_SETFD, FD_CLOEXEC);
  fcntl (from[1], F_SETFD, FD_CLOEXEC);

  posix_spawn_file_actions_t fa;

  int rc = posix_spawn_file_actions_init (&fa);

  if (rc != 0)
  {
    close (to[0]);
    close (to[1]);
    close (from[0]);
    close (from[1]);

    errno = rc;

    return false;
  }

  // Without both of these the spawn still succeeds, and the worker then inherits hashcat's own standard
  // input and output and writes its first frame onto the terminal. They are checked for that reason.

  rc = posix_spawn_file_actions_adddup2 (&fa, to[0], 0);

  if (rc == 0) rc = posix_spawn_file_actions_adddup2 (&fa, from[1], 1);

  pid_t pid = 0;

  if (rc == 0) rc = posix_spawnp (&pid, python, &fa, NULL, argv, envp);

  posix_spawn_file_actions_destroy (&fa);

  close (to[0]);
  close (from[1]);

  if (rc != 0)
  {
    close (to[1]);
    close (from[0]);

    errno = rc;

    return false;
  }

  worker->pid         = pid;
  worker->to_worker   = to[1];
  worker->from_worker = from[0];
  worker->running     = true;

  return true;
}

static bool worker_write (worker_t *worker, const void *buf, const size_t len)
{
  const u8 *ptr = (const u8 *) buf;

  size_t done = 0;

  while (done < len)
  {
    const ssize_t rc = write (worker->to_worker, ptr + done, len - done);

    if (rc == -1)
    {
      if (errno == EINTR) continue;

      return false;
    }

    done += (size_t) rc;
  }

  return true;
}

static bool worker_read (worker_t *worker, void *buf, const size_t len)
{
  u8 *ptr = (u8 *) buf;

  size_t done = 0;

  while (done < len)
  {
    const ssize_t rc = read (worker->from_worker, ptr + done, len - done);

    if (rc == -1)
    {
      if (errno == EINTR) continue;

      return false;
    }

    if (rc == 0) return false;

    done += (size_t) rc;
  }

  return true;
}

static void worker_stop (worker_t *worker)
{
  if (worker->running == false) return;

  // Closing its input is the worker's signal to finish, and a worker between batches exits at once.
  // One interrupted in the middle of a batch has a candidate to finish first, and a plugin that never
  // returns would hold hashcat here for good, so the wait is bounded and what is left gets killed.

  close (worker->to_worker);
  close (worker->from_worker);

  int status = 0;

  bool reaped = false;

  for (int i = 0; i < (WORKER_EXIT_MSEC / 10); i++)
  {
    const pid_t rc = waitpid (worker->pid, &status, WNOHANG);

    if (rc == -1)
    {
      if (errno == EINTR) continue;

      reaped = true;

      break;
    }

    if (rc == worker->pid)
    {
      reaped = true;

      break;
    }

    usleep (10 * 1000);
  }

  if (reaped == false)
  {
    kill (worker->pid, SIGKILL);

    while ((waitpid (worker->pid, &status, 0) == -1) && (errno == EINTR)) {}
  }

  worker->killed  = (reaped == false);
  worker->running = false;
}

#endif

static bool frame_write (worker_t *worker, const u32 type, const u8 *payload, const u32 len)
{
  u32 head[2];

  head[0] = type;
  head[1] = len;

  if (worker_write (worker, head, sizeof (head)) == false) return false;

  if (len == 0) return true;

  const bool rc = worker_write (worker, payload, len);

  return rc;
}

// Whatever the interpreter printed to its standard output before the worker ran would otherwise be read
// as the first frame, and a .pth file or a sitecustomize.py that prints is the way that happens. The
// worker leads with MAGIC, so this skips to it and reports what came before as the interpreter's own
// output instead of as a frame type nobody can act on.

// How much output the interpreter may print before the greeting before this gives up. An interpreter
// that prints in a loop would otherwise hold hashcat here for as long as it keeps printing.

#define WORKER_NOISE_MAX 4096

// What the interpreter printed is logged, so it is clamped to printable ASCII first. It is bytes from
// another process, and an escape sequence in it would be acted on by the terminal rather than shown.

static void noise_add (char *noise, u32 *noise_len, const u8 c)
{
  if (*noise_len >= (WORKER_NOISE_MAX - 1)) return;

  noise[(*noise_len)++] = ((c >= 0x20) && (c <= 0x7e)) ? (char) c : '.';
}

static bool worker_sync (hashcat_ctx_t *hashcat_ctx, worker_t *worker)
{
  u8 seen[sizeof (WORKER_MAGIC) - 1];

  if (worker_read (worker, seen, sizeof (seen)) == false)
  {
    event_log_error (hashcat_ctx, "The Python worker exited before it said anything. Its own error, if it printed one, is above.");

    return false;
  }

  char noise[WORKER_NOISE_MAX];

  u32 noise_len = 0;

  bool found = true;

  while (memcmp (seen, WORKER_MAGIC, sizeof (seen)) != 0)
  {
    noise_add (noise, &noise_len, seen[0]);

    memmove (seen, seen + 1, sizeof (seen) - 1);

    if (noise_len >= (WORKER_NOISE_MAX - 1))
    {
      found = false;

      break;
    }

    if (worker_read (worker, &seen[sizeof (seen) - 1], 1) == false)
    {
      // what is still in the window is the end of what it printed, so it belongs in the message

      for (size_t i = 0; i < (sizeof (seen) - 1); i++) noise_add (noise, &noise_len, seen[i]);

      found = false;

      break;
    }
  }

  noise[noise_len] = 0;

  if (found == false)
  {
    event_log_error (hashcat_ctx, "The Python interpreter printed this instead of talking to hashcat: %s", noise);
    event_log_error (hashcat_ctx, "Something it runs at startup writes to standard output, which this protocol owns.");

    return false;
  }

  if (noise_len > 0)
  {
    event_log_warning (hashcat_ctx, "The Python interpreter printed this before starting: %s", noise);
  }

  return true;
}

// Reads one frame into a buffer that grows as needed. An ERROR frame is reported here, so a caller
// only has to give up when this returns false.

static bool frame_read (hashcat_ctx_t *hashcat_ctx, worker_t *worker, const u32 want, u8 **buf, size_t *size, u32 *len)
{
  u32 head[2];

  if (worker_read (worker, head, sizeof (head)) == false)
  {
    event_log_error (hashcat_ctx, "The Python worker exited unexpectedly. Its own error, if it printed one, is above.");

    return false;
  }

  const u32 type = head[0];

  *len = head[1];

  if (*len > FRAME_LEN_MAX)
  {
    event_log_error (hashcat_ctx, "The Python worker announced a %u byte frame, where the largest this protocol has is %u.", *len, (u32) FRAME_LEN_MAX);

    return false;
  }

  // A terminating zero past the payload, so an ERROR frame can be logged as the string it is.

  if (buf_reserve (buf, size, (size_t) *len + 1) == false)
  {
    event_log_error (hashcat_ctx, "Out of memory for a %u byte reply from the Python worker.", *len);

    return false;
  }

  if ((*len > 0) && (worker_read (worker, *buf, *len) == false))
  {
    event_log_error (hashcat_ctx, "The Python worker exited in the middle of a reply.");

    return false;
  }

  (*buf)[*len] = 0;

  if (type == FRAME_ERROR)
  {
    event_log_error (hashcat_ctx, "%s", (const char *) *buf);

    return false;
  }

  if (type != want)
  {
    event_log_error (hashcat_ctx, "The Python worker answered with frame type %u where %u was expected.", type, want);

    return false;
  }

  return true;
}

// A frame comes from another process, so every read out of one is bounds checked. Both helpers leave
// *pos where it was when they refuse, and *pos is never allowed past len, which is what keeps the
// subtraction below from wrapping.

static bool u32_take (const u8 *buf, const u32 len, u32 *pos, u32 *value)
{
  if (((u64) *pos + 4) > (u64) len) return false;

  memcpy (value, buf + *pos, 4);

  *pos += 4;

  return true;
}

static bool blob_take (const u8 *buf, const u32 len, u32 *pos, const u8 **data, u32 *data_len)
{
  u32 take = *pos;

  u32 n = 0;

  if (u32_take (buf, len, &take, &n) == false) return false;

  if (((u64) take + n) > (u64) len) return false;

  *data     = buf + take;
  *data_len = n;

  *pos = take + n;

  return true;
}

static bool u32_put (u8 **buf, size_t *size, u32 *pos, const u32 value)
{
  if (buf_reserve (buf, size, (size_t) *pos + 4) == false) return false;

  memcpy (*buf + *pos, &value, 4);

  *pos += 4;

  return true;
}

// A length travels as a u32 and a frame is addressed by one, so a blob that does not fit in a u32 is
// refused rather than truncated. Only the salt table of an enormous hash list can reach that, and the
// pipe would be the wrong way to move it anyway.

static bool blob_put (u8 **buf, size_t *size, u32 *pos, const void *data, const size_t data_len)
{
  if (data_len > (0xffffffff - 4 - (size_t) *pos)) return false;

  const u32 len = (u32) data_len;

  if (u32_put (buf, size, pos, len) == false) return false;

  if (buf_reserve (buf, size, (size_t) *pos + len) == false) return false;

  if (len > 0) memcpy (*buf + *pos, data, len);

  *pos += len;

  return true;
}

// Every worker introduces itself first. The probe in platform_init () keeps what it says, and the
// workers of the units only confirm they speak the same protocol.

static bool worker_hello (hashcat_ctx_t *hashcat_ctx, worker_t *worker, u8 **buf, size_t *size, char **version, char **st_hash, char **st_pass)
{
  if (worker_sync (hashcat_ctx, worker) == false) return false;

  u32 len = 0;

  if (frame_read (hashcat_ctx, worker, FRAME_HELLO, buf, size, &len) == false) return false;

  u32 pos = 0;

  u32 protocol = 0;

  u32 salt_t_size = 0;

  if ((u32_take (*buf, len, &pos, &protocol) == false) || (u32_take (*buf, len, &pos, &salt_t_size) == false))
  {
    event_log_error (hashcat_ctx, "The Python worker sent a malformed greeting.");

    return false;
  }

  if (protocol != PROTOCOL_VERSION)
  {
    event_log_error (hashcat_ctx, "Python/hcworker.py speaks protocol %u, this hashcat speaks %u. The Python folder does not belong to this build.", protocol, PROTOCOL_VERSION);

    return false;
  }

  if (salt_t_size != sizeof (salt_t))
  {
    event_log_error (hashcat_ctx, "Python/hcshared.py unpacks a %u byte salt_t and this hashcat has %u. The Python folder does not belong to this build.", salt_t_size, (u32) sizeof (salt_t));

    return false;
  }

  char **out[3] = { version, st_hash, st_pass };

  for (int i = 0; i < 3; i++)
  {
    const u8 *data = NULL;

    u32 data_len = 0;

    if (blob_take (*buf, len, &pos, &data, &data_len) == false)
    {
      event_log_error (hashcat_ctx, "The Python worker sent a malformed greeting.");

      return false;
    }

    if (out[i] == NULL) continue;

    *out[i] = (char *) hcmalloc (data_len + 1);

    if (*out[i] == NULL) return false;

    memcpy (*out[i], data, data_len);

    (*out[i])[data_len] = 0;
  }

  return true;
}

// What the operating system said about a spawn that failed. Win32 reports through GetLastError () and
// leaves errno alone, so reading errno there prints whatever an unrelated call left behind.

static void worker_launch_reason (char *buf, const size_t buf_size)
{
  #if defined (_WIN)

  const DWORD err = GetLastError ();

  if (FormatMessageA (FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, 0, buf, (DWORD) buf_size, NULL) == 0)
  {
    snprintf (buf, buf_size, "Win32 error %u", (u32) err);

    return;
  }

  // FormatMessage ends its text with a newline, which would break the log line in two

  for (size_t i = 0; i < buf_size; i++)
  {
    if (buf[i] == 0) break;

    if ((buf[i] == '\r') || (buf[i] == '\n'))
    {
      buf[i] = 0;

      break;
    }
  }

  #else

  snprintf (buf, buf_size, "%s", strerror (errno));

  #endif
}

static bool worker_launch (hashcat_ctx_t *hashcat_ctx, bridge_context_t *bridge_context, worker_t *worker)
{
  hc_thread_mutex_lock (bridge_context->spawn_mutex);

  const bool started = worker_start (worker, bridge_context->python, bridge_context->worker_path, bridge_context->plugin_path);

  char reason[512];

  reason[0] = 0;

  if (started == false) worker_launch_reason (reason, sizeof (reason));

  hc_thread_mutex_unlock (bridge_context->spawn_mutex);

  if (started == true) return true;

  event_log_error (hashcat_ctx, "Cannot start the Python interpreter '%s': %s", bridge_context->python, reason);
  event_log_error (hashcat_ctx, "Install Python 3, activate the environment that holds your plugin's modules, or name the interpreter with --bridge-parameter2.");

  return false;
}

static void units_term (bridge_context_t *bridge_context)
{
  if (bridge_context->units_buf == NULL) return;

  for (int i = 0; i < bridge_context->units_cnt; i++)
  {
    unit_t *unit_buf = &bridge_context->units_buf[i];

    worker_stop (&unit_buf->worker);

    hcfree (unit_buf->send_buf);
    hcfree (unit_buf->recv_buf);
  }

  hcfree (bridge_context->units_buf);

  bridge_context->units_buf = NULL;
}

static bool units_init (hashcat_ctx_t *hashcat_ctx, bridge_context_t *bridge_context)
{
  const int num_devices = hc_get_processor_count ();

  // sysconf () answers -1 in a restricted container, and the core passes that through. A unit count
  // the core cannot use is reported here rather than handed on as a negative device count.

  if (num_devices < 1)
  {
    event_log_error (hashcat_ctx, "This machine reports %d processors, so there is nothing to run a Python worker on.", num_devices);

    return false;
  }

  unit_t *units_buf = (unit_t *) hccalloc (num_devices, sizeof (unit_t));

  if (units_buf == NULL) return false;

  for (int i = 0; i < num_devices; i++)
  {
    unit_t *unit_buf = &units_buf[i];

    snprintf (unit_buf->unit_info_buf, sizeof (unit_buf->unit_info_buf), "Python %s worker", bridge_context->version);
  }

  bridge_context->units_buf = units_buf;
  bridge_context->units_cnt = num_devices;

  return true;
}

// Everything platform_init () has brought up by the point one of its returns is taken. The context
// comes from hcmalloc (), which zeroes, so a field a return has not reached yet is NULL and the free
// of it is a no-op. platform_term () does not run for a platform that never came up, so the mutex is
// released here rather than there.

static void context_free (bridge_context_t *bridge_context)
{
  units_term (bridge_context);

  hcfree (bridge_context->python);
  hcfree (bridge_context->worker_path);
  hcfree (bridge_context->plugin_path);
  hcfree (bridge_context->version);
  hcfree (bridge_context->st_hash);
  hcfree (bridge_context->st_pass);
  hcfree (bridge_context->init_buf);

  #if !defined (_WIN)

  // Put the process wide disposition back. This is here rather than in platform_term () because
  // platform_term () does not run for a platform that never came up, and a sweep over the hash modes
  // carries on past one that could not start: leaving it ignored would reach every later mode.

  if (bridge_context->sigpipe_saved != SIG_ERR) signal (SIGPIPE, bridge_context->sigpipe_saved);

  #endif

  hc_thread_mutex_delete (bridge_context->spawn_mutex);

  hcfree (bridge_context);
}

void *platform_init (hashcat_ctx_t *hashcat_ctx)
{
  if (cpu_chipset_test () == -1) return NULL;

  const folder_config_t *folder_config = hashcat_ctx->folder_config;
  const user_options_t  *user_options  = hashcat_ctx->user_options;

  bridge_context_t *bridge_context = (bridge_context_t *) hcmalloc (sizeof (bridge_context_t));

  if (bridge_context == NULL) return NULL;

  hc_thread_mutex_init (bridge_context->spawn_mutex);

  #if !defined (_WIN)

  // A worker that died leaves a pipe nobody reads, and writing to it raises SIGPIPE, which would end
  // hashcat without a word. Ignored, the write fails instead and the bridge says which worker died.
  //
  // The disposition belongs to the whole process, and nothing else in hashcat sets it, so what was
  // there is put back in platform_term (). Leaving it ignored would outlive the bridge into every other
  // hash mode of a --benchmark-all sweep.

  bridge_context->sigpipe_saved = signal (SIGPIPE, SIG_IGN);

  #endif

  hc_asprintf (&bridge_context->worker_path, "%s/%s", folder_config->shared_dir, WORKER_FILENAME);

  if (user_options->bridge_parameter1 != NULL)
  {
    bridge_context->plugin_path = hcstrdup (user_options->bridge_parameter1);
  }
  else
  {
    hc_asprintf (&bridge_context->plugin_path, "%s/%s", folder_config->shared_dir, DEFAULT_PLUGIN);
  }

  bridge_context->python = hcstrdup ((user_options->bridge_parameter2 != NULL) ? user_options->bridge_parameter2 : DEFAULT_PYTHON);

  bridge_context->bridge_parameter[0] = user_options->bridge_parameter1;
  bridge_context->bridge_parameter[1] = user_options->bridge_parameter2;
  bridge_context->bridge_parameter[2] = user_options->bridge_parameter3;
  bridge_context->bridge_parameter[3] = user_options->bridge_parameter4;

  // One worker started here and stopped again proves the interpreter and the plugin load, and brings
  // back the self-test pair, before hashcat sets up anything that depends on them.

  worker_t probe;

  memset (&probe, 0, sizeof (probe));

  if (worker_launch (hashcat_ctx, bridge_context, &probe) == false)
  {
    context_free (bridge_context);

    return NULL;
  }

  u8    *buf  = NULL;
  size_t size = 0;

  const bool hello = worker_hello (hashcat_ctx, &probe, &buf, &size, &bridge_context->version, &bridge_context->st_hash, &bridge_context->st_pass);

  hcfree (buf);

  worker_stop (&probe);

  if (hello == false)
  {
    context_free (bridge_context);

    return NULL;
  }

  // The self test is the one check that the plugin computes what the hash line says, so a plugin
  // without the pair is refused here. The alternative was an empty self test hash, which the core
  // parses before it can report anything, and that is where this used to end in a segfault.

  if ((bridge_context->st_hash[0] == 0) || (bridge_context->st_pass[0] == 0))
  {
    event_log_error (hashcat_ctx, "%s: ST_HASH and ST_PASS are both required.", bridge_context->plugin_path);
    event_log_error (hashcat_ctx, "They are a hash line and the password that produces it, and hashcat checks the pair before every run.");

    context_free (bridge_context);

    return NULL;
  }

  if (units_init (hashcat_ctx, bridge_context) == false)
  {
    context_free (bridge_context);

    return NULL;
  }

  return bridge_context;
}

void platform_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  bridge_context_t *bridge_context = platform_context;

  if (bridge_context == NULL) return;

  context_free (bridge_context);
}

// Builds the INIT payload the first time it is asked and keeps it. Every unit is sent the same bytes,
// and hashes and hashconfig describe the one hash list for the whole run, so one build serves the self
// test phase and the cracking phase alike. init_len is what says it is ready, and it is only ever
// written once, so a reader that saw a non-zero length can use the buffer without the lock.

static bool init_build (hashcat_ctx_t *hashcat_ctx, bridge_context_t *bridge_context, const hashconfig_t *hashconfig, const hashes_t *hashes)
{
  hc_thread_mutex_lock (bridge_context->spawn_mutex);

  if (bridge_context->init_len > 0)
  {
    hc_thread_mutex_unlock (bridge_context->spawn_mutex);

    return true;
  }

  const u32 salt_per_pw = (hashcat_ctx->user_options->attack_mode == ATTACK_MODE_ASSOCIATION) ? 1 : 0;

  u32 pos = 0;

  bool ok = u32_put (&bridge_context->init_buf, &bridge_context->init_size, &pos, salt_per_pw);

  // The sizes the two sides have to agree on. hcshared.py refuses a salt_t it unpacks differently, and
  // esalt_size is the record length a plugin's extract_esalts () has to step by, which it cannot work
  // out from the blob alone.

  ok = ok && u32_put (&bridge_context->init_buf, &bridge_context->init_size, &pos, (u32) sizeof (salt_t));
  ok = ok && u32_put (&bridge_context->init_buf, &bridge_context->init_size, &pos, (u32) hashconfig->esalt_size);

  ok = ok && blob_put (&bridge_context->init_buf, &bridge_context->init_size, &pos, hashes->salts_buf,     (size_t) hashes->salts_cnt   * sizeof (salt_t));
  ok = ok && blob_put (&bridge_context->init_buf, &bridge_context->init_size, &pos, hashes->esalts_buf,    (size_t) hashes->digests_cnt * hashconfig->esalt_size);
  ok = ok && blob_put (&bridge_context->init_buf, &bridge_context->init_size, &pos, hashes->st_salts_buf,  sizeof (salt_t));
  ok = ok && blob_put (&bridge_context->init_buf, &bridge_context->init_size, &pos, hashes->st_esalts_buf, hashconfig->esalt_size);

  for (int i = 0; i < 4; i++)
  {
    const char *param = bridge_context->bridge_parameter[i];

    ok = ok && blob_put (&bridge_context->init_buf, &bridge_context->init_size, &pos, param, (param == NULL) ? 0 : strlen (param));
  }

  if (ok == true) bridge_context->init_len = pos;

  hc_thread_mutex_unlock (bridge_context->spawn_mutex);

  if (ok == false) event_log_error (hashcat_ctx, "This hash list is too large to hand to a Python worker.");

  return ok;
}

bool thread_init (hashcat_ctx_t *hashcat_ctx, void *platform_context, hc_device_param_t *device_param, hashconfig_t *hashconfig, hashes_t *hashes)
{
  bridge_context_t *bridge_context = platform_context;

  unit_t *unit_buf = &bridge_context->units_buf[device_param->bridge_link_device];

  worker_t *worker = &unit_buf->worker;

  if (worker_launch (hashcat_ctx, bridge_context, worker) == false) return false;

  if (worker_hello (hashcat_ctx, worker, &unit_buf->recv_buf, &unit_buf->recv_size, NULL, NULL, NULL) == false)
  {
    worker_stop (worker);

    return false;
  }

  // INIT: the two sizes the sides agree on, the salts and esalts of the run and of the self test, and
  // the four bridge parameters. A unit holds its own copy of all of them for the whole run, so a batch
  // carries nothing but candidates.
  //
  // It is the same bytes for every unit, and on a large hash list those bytes are the tables. Building
  // it per unit held one copy per unit at once, which on 28 units and 20000 salts came to over a
  // gigabyte of identical data, so it is built on whichever unit gets here first and shared.

  if (init_build (hashcat_ctx, bridge_context, hashconfig, hashes) == false)
  {
    worker_stop (worker);

    return false;
  }

  if (frame_write (worker, FRAME_INIT, bridge_context->init_buf, bridge_context->init_len) == false)
  {
    event_log_error (hashcat_ctx, "The Python worker of unit %d exited before it was given its salts.", device_param->bridge_link_device + 1);

    worker_stop (worker);

    return false;
  }

  u32 len = 0;

  if (frame_read (hashcat_ctx, worker, FRAME_READY, &unit_buf->recv_buf, &unit_buf->recv_size, &len) == false)
  {
    worker_stop (worker);

    return false;
  }

  return true;
}

void thread_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  bridge_context_t *bridge_context = platform_context;

  unit_t *unit_buf = &bridge_context->units_buf[device_param->bridge_link_device];

  worker_stop (&unit_buf->worker);

  // A worker that had to be killed did not finish what it was doing, and a plugin's term () is part of
  // that. Saying so is the difference between a teardown that was cut off and one that completed.

  if (unit_buf->worker.killed == true)
  {
    event_log_warning (hashcat_ctx, "The Python worker of unit %d did not exit within %d ms and was killed, so its term () may not have finished.", device_param->bridge_link_device + 1, WORKER_EXIT_MSEC);
  }
}

int get_unit_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  bridge_context_t *bridge_context = platform_context;

  return bridge_context->units_cnt;
}

int get_workitem_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED const int unit_idx)
{
  return WORKITEM_COUNT_MAX;
}

// One unit is one process working through its batch sequentially, so there is no width to fill and a
// batch of N costs N hashes whatever N is. Parallelism is the number of units.

int get_workitem_multiple (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED const int unit_idx)
{
  return 1;
}

char *get_unit_info (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_context_t *bridge_context = platform_context;

  return bridge_context->units_buf[unit_idx].unit_info_buf;
}

bool launch_loop (hashcat_ctx_t *hashcat_ctx, void *platform_context, hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, hashes_t *hashes, const u32 salt_pos, const u64 pws_cnt)
{
  bridge_context_t *bridge_context = platform_context;

  unit_t *unit_buf = &bridge_context->units_buf[device_param->bridge_link_device];

  worker_t *worker = &unit_buf->worker;

  generic_io_tmp_t *generic_io_tmp = (generic_io_tmp_t *) device_param->h_tmps;

  // BATCH: the salt the batch starts at, whether it is the self-test, then every candidate. The
  // worker adds the candidate's own position to the salt when salt_per_pw was set in INIT.

  const u32 batch_head[3] =
  {
    bridge_salt_pos (hashcat_ctx, device_param, hashes, salt_pos, 0),
    (hashes->salts_buf == hashes->st_salts_buf) ? 1 : 0,
    (u32) pws_cnt,
  };

  if (buf_reserve (&unit_buf->send_buf, &unit_buf->send_size, sizeof (batch_head) + (pws_cnt * (4 + PW_LEN_MAX))) == false) return false;

  memcpy (unit_buf->send_buf, batch_head, sizeof (batch_head));

  u32 pos = sizeof (batch_head);

  for (u64 i = 0; i < pws_cnt; i++)
  {
    const u32 pw_len = MIN (generic_io_tmp[i].pw_len, PW_LEN_MAX);

    if (blob_put (&unit_buf->send_buf, &unit_buf->send_size, &pos, generic_io_tmp[i].pw_buf, pw_len) == false) return false;
  }

  if (frame_write (worker, FRAME_BATCH, unit_buf->send_buf, pos) == false)
  {
    event_log_error (hashcat_ctx, "The Python worker of unit %d exited. Its own error, if it printed one, is above.", device_param->bridge_link_device + 1);

    return false;
  }

  u32 len = 0;

  if (frame_read (hashcat_ctx, worker, FRAME_RESULT, &unit_buf->recv_buf, &unit_buf->recv_size, &len) == false) return false;

  // RESULT: the candidate count, then for every candidate the count of its values and each value

  const u8 *buf = unit_buf->recv_buf;

  pos = 0;

  u32 count = 0;

  if (u32_take (buf, len, &pos, &count) == false)
  {
    event_log_error (hashcat_ctx, "The Python worker sent a truncated result.");

    return false;
  }

  if (count != pws_cnt)
  {
    event_log_error (hashcat_ctx, "The Python worker returned %u results for %u candidates.", count, (u32) pws_cnt);

    return false;
  }

  for (u64 i = 0; i < pws_cnt; i++)
  {
    u32 out_cnt = 0;

    if ((u32_take (buf, len, &pos, &out_cnt) == false) || (out_cnt > OUT_CNT_MAX))
    {
      event_log_error (hashcat_ctx, "The Python worker sent a malformed result.");

      return false;
    }

    for (u32 j = 0; j < out_cnt; j++)
    {
      const u8 *data = NULL;

      u32 data_len = 0;

      if ((blob_take (buf, len, &pos, &data, &data_len) == false) || (data_len > OUT_LEN_MAX))
      {
        event_log_error (hashcat_ctx, "The Python worker sent a malformed result.");

        return false;
      }

      memcpy (generic_io_tmp[i].out_buf[j], data, data_len);

      generic_io_tmp[i].out_len[j] = data_len;
    }

    generic_io_tmp[i].out_cnt = out_cnt;
  }

  return true;
}

const char *st_update_hash (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  bridge_context_t *bridge_context = platform_context;

  return bridge_context->st_hash;
}

const char *st_update_pass (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  bridge_context_t *bridge_context = platform_context;

  return bridge_context->st_pass;
}

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  bridge_ctx->bridge_context_size        = BRIDGE_CONTEXT_SIZE_CURRENT;
  bridge_ctx->bridge_interface_version   = BRIDGE_INTERFACE_VERSION_CURRENT;

  bridge_ctx->platform_init              = platform_init;
  bridge_ctx->platform_term              = platform_term;
  bridge_ctx->get_unit_count             = get_unit_count;
  bridge_ctx->get_unit_info              = get_unit_info;
  bridge_ctx->get_workitem_count         = get_workitem_count;
  bridge_ctx->get_workitem_multiple      = get_workitem_multiple;
  bridge_ctx->thread_init                = thread_init;
  bridge_ctx->thread_term                = thread_term;
  bridge_ctx->salt_prepare               = BRIDGE_DEFAULT;
  bridge_ctx->salt_destroy               = BRIDGE_DEFAULT;
  bridge_ctx->launch_loop                = launch_loop;
  bridge_ctx->launch_loop2               = BRIDGE_DEFAULT;
  bridge_ctx->st_update_hash             = st_update_hash;
  bridge_ctx->st_update_pass             = st_update_pass;
  bridge_ctx->get_unit_temperature       = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_temperature_str   = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_temperature_abort = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_fanspeed          = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_utilization       = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_corespeed         = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_memoryspeed       = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_buslanes          = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_power             = BRIDGE_DEFAULT;
}
