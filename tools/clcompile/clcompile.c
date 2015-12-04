/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <CL/cl.h>

#define CL_PLATFORMS_MAX  128
#define CL_DEVICES_MAX    128

//char options[] = "–x spir -spir-std=1.2 -I.";
char options[] = "-I. -x clc++ -cl-std=CL1.2";

static void checkErr (char *func, cl_int err)
{
  if (err != CL_SUCCESS)
  {
    fprintf (stderr, "%s(): ", func);

    switch (err)
    {
      case CL_BUILD_PROGRAM_FAILURE :
      fprintf (stderr, "CL_BUILD_PROGRAM_FAILURE");
      break;

      case CL_COMPILER_NOT_AVAILABLE :
      fprintf (stderr, "CL_COMPILER_NOT_AVAILABLE");
      break;

      case CL_DEVICE_NOT_AVAILABLE :
      fprintf (stderr, "CL_DEVICE_NOT_AVAILABLE");
      break;

      case CL_DEVICE_NOT_FOUND :
      fprintf (stderr, "CL_DEVICE_NOT_FOUND");
      break;

      case CL_INVALID_BINARY :
      fprintf (stderr, "CL_INVALID_BINARY");
      break;

      case CL_INVALID_BUILD_OPTIONS :
      fprintf (stderr, "CL_INVALID_BUILD_OPTIONS");
      break;

      case CL_INVALID_CONTEXT :
      fprintf (stderr, "CL_INVALID_CONTEXT");
      break;

      case CL_INVALID_DEVICE :
      fprintf (stderr, "CL_INVALID_DEVICE");
      break;

      case CL_INVALID_DEVICE_TYPE :
      fprintf (stderr, "CL_INVALID_DEVICE_TYPE");
      break;

      case CL_INVALID_OPERATION :
      fprintf (stderr, "CL_INVALID_OPERATION");
      break;

      case CL_INVALID_PLATFORM :
      fprintf (stderr, "CL_INVALID_PLATFORM");
      break;

      case CL_INVALID_PROGRAM :
      fprintf (stderr, "CL_INVALID_PROGRAM");
      break;

      case CL_INVALID_VALUE :
      fprintf (stderr, "CL_INVALID_VALUE");
      break;

      case CL_OUT_OF_HOST_MEMORY :
      fprintf (stderr, "CL_OUT_OF_HOST_MEMORY");
      break;

      default :
      fprintf (stderr, "Unknown error code: %d", err);
      break;
    }

    fprintf (stderr, "\n");

    exit (err);
  }
}

static char *load_kernel (const char *kernel_file)
{
  FILE *fp = NULL;

  if ((fp = fopen (kernel_file, "rb")) != NULL)
  {
    struct stat st;

    if (stat (kernel_file, &st) == -1)
    {
      fprintf (stderr, "! stat() failed (%d) : %s\n", errno, strerror (errno));
    }

    char *buf = (char *) malloc (st.st_size + 1);

    memset (buf, 0, st.st_size + 1);

    size_t num_read = fread (buf, sizeof (char), st.st_size, fp);

    if (num_read != (size_t) st.st_size)
    {
      fprintf (stderr, "! fread() [%s] failed (%d) : %s", kernel_file, errno, strerror (errno));
      fclose (fp);
      exit (-1);
    }

    fclose (fp);

    return buf;
  }
  else
  {
    fprintf (stderr, "! fopen() [%s] failed (%d) : %s", kernel_file, errno, strerror (errno));
    exit (-1);
  }

  return NULL;
}

static int writeProgramBins (char *dst, unsigned char *binary, size_t binary_size)
{
  FILE *fp = fopen (dst, "wb");

  if (!fp)
  {
    fprintf(stderr, "! fopen() [%s] failed (%d) : %s\n", dst, errno, strerror (errno));
    return -1;
  }

  if (fwrite (binary, sizeof (unsigned char), binary_size, fp) != binary_size)
  {
    fprintf(stderr, "! fwrite() [%s] failed (%d) : %s\n", dst, errno, strerror (errno));
    fclose (fp);
    return -1;
  }

  fclose (fp);

  return 0;
}

int main (int argc, char *argv[])
{
  if (argc != 4)
  {
    fprintf (stderr, "> Usage: %s ccopts src dst\n", argv[0]);

    return (-1);
  }

  char *ccopts = argv[1];
  char *src    = argv[2];
  char *dst    = argv[3];

  char *programSrc = load_kernel (src);

  if (programSrc == NULL)
  {
    fprintf (stderr, "Unable to open %s. Exiting.\n", src);

    return (-1);
  }

  cl_device_id devices[1];
  cl_uint nDevices;

  cl_platform_id platform;
  cl_uint platforms;

  cl_int err;

  err = clGetPlatformIDs(1, &platform, &platforms);

  checkErr ((char *) "clGetPlatformIDs", err);

  err = clGetDeviceIDs (platform, CL_DEVICE_TYPE_GPU, 1, devices, &nDevices);

  checkErr ((char *) "clGetDeviceIDs", err);

  cl_context context = clCreateContext (NULL, 1, devices, NULL, NULL, &err);

  checkErr ((char *) "clCreateContext", err);

  cl_program program = clCreateProgramWithSource (context, 1, (const char **) &programSrc, NULL, &err);

  checkErr ((char *) "clCreateProgramWithSource", err);

  size_t opt_len = strlen (ccopts) + 1 + strlen (options) + 1;

  char *options2 = (char *) malloc (opt_len + 1);

  memset (options2, 0, opt_len + 1);

  snprintf (options2, opt_len, "%s %s", options, ccopts);

  err = clCompileProgram (program, 1, devices, options2, 0, NULL, NULL, NULL, NULL);

  //checkErr ((char *) "clCompileProgram", err);

  size_t ret_val_size = 0;

  err = clGetProgramBuildInfo (program, devices[0], CL_PROGRAM_BUILD_LOG, 0, NULL, &ret_val_size);

  checkErr ((char *) "clGetProgramBuildInfo", err);

  if (ret_val_size > 1)
  {
    char *build_log = (char *) malloc (ret_val_size + 1);

    memset (build_log, 0, ret_val_size + 1);

    err = clGetProgramBuildInfo (program, devices[0], CL_PROGRAM_BUILD_LOG, ret_val_size, build_log, NULL);

    checkErr ((char *) "clGetProgramBuildInfo", err);

    puts (build_log);
  }

  size_t binary_size;

  err = clGetProgramInfo (program, CL_PROGRAM_BINARY_SIZES, sizeof (size_t), &binary_size, NULL);

  checkErr ((char *) "clGetProgramInfo", err);

  unsigned char *binary = (unsigned char *) malloc (binary_size);

  memset(binary, 0, binary_size);

  err = clGetProgramInfo (program, CL_PROGRAM_BINARIES, sizeof (binary), &binary, NULL);

  checkErr ((char *) "clGetProgramInfo", err);

  err = writeProgramBins (dst, binary, binary_size);

  checkErr ((char *) "writeProgramBins", err);

  return 0;
}
