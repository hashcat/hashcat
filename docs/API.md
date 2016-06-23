# Hashcat API (Beta)

## Overview
Fundamentally the API is simply constructing command line arguments (argv) to pass to the existing hashcat main function. The arguments are constructed by comparing the default value of a variable to the currently assigned value. If there is a change then the command is added to the argv array. 

The core of the API is located in the src/hashcatAPI.c source file 

## Compiling and Macros

When using the API use the -DAPI compiler flag. This is already included in the Make file. For testing purposes you only have to type

    make win64API win32API linux64API linux32API installAPI

Using the -DDEBUG flag will produce more verbose debugging output to help with development. 

## Functions

###struct hcapi_control_t oclhashcat_init (void)

Function to initialize a useful API data structure - `hcapi_control`, which is explained below. The intent is for this to be the first function called when accessing the API


###int hcapi_main (int, char **)

When the -DAPI compiler flag is used this becomes the new entry to point to the main oclHashcat code path. In other words, this used to the main().

###int hcapi_start (int, char **)

Wrapper to pass command line arguments to the hcapi_main function.

###int hcapi_stop (void)

Stop oclHashcat process. This is calling the `myabort` function.

###void hcapi_append_rules (struct hcapi_options_t *, char *)

Builds a comma separated list of paths to files containing rules.

###void hcapi_append_dictmaskdir (struct hcapi_options_t *, char *)

Builds a comma separated list of paths/strings to files or directories containing dictionaries, masks or other positional input.

###void hcapi_generate_commandline (struct hcapi_options_t, int *, char ***)

Compares the default parameter values to the currently assigned values. Any delta is appended and stored in the argv parameter (char ***)

###int hcapi_status_update (struct hcapi_data_t *)

This function is derived from the `status_display` function located in hashcat.c. `hcapi_status_update` will take a *snap shot* of the current status of the running hashcat instance. See below for usage example. 

###HANDLE hcapi_start_thread (int, char **)

Starts hashcat in a background thread (WIN)

###int hcapi_start_thread (int, char **)

Starts hashcat in a background thread (POSIX)

###void check_argv_array (char ***, size_t *, size_t *, int *)

Internal function to check the size of the argv array and expand as needed.

###char *strcat_ls (char *, char *)

Internal function for string concatenation.

## Data Structures

###struct hcapi_control_t  

This structure is returned by the oclhashcat_init() function, and provides the following convenience functions controlling oclHashcat programmatically

`start, stop, generate_commandline, get_data, start_thread`

See below for usage example.

###struct hcapi_options_t

This structure holds all the various command line variables for hashcat. Each option can be accessed/assigned via the dot operator.

###struct hcapi_thread_args_t

This structure is used by hcapi_start_thread to pass multiple args to the thread creation functions. 

###struct hcapi_data_t

This structure holds all the status data about the running hashcat process. 

**NOTE: The structures below were designed to help organize the status data. If there is a better approach all ideas are welcome**

###hcapi_data_time_started_t

See example below for accessing status data within this structure.

###hcapi_data_time_estimated_t

See example below for accessing status data within this structure.

###hcapi_data_speed_dev_t

See example below for accessing status data within this structure.

###hcapi_data_recovered_t

See example below for accessing status data within this structure.

###hcapi_data_recovered_time_t

See example below for accessing status data within this structure.

###hcapi_data_progress_t

See example below for accessing status data within this structure.

###hcapi_data_restore_point_t

See example below for accessing status data within this structure.

###hcapi_data_hwmon_gpu_t

See example below for accessing status data within this structure.


## Design

Using the API compiler flag will rename `main` in hashcat.c to `hcapi_main`. This allows developers to construct their own entry point. The intent is then for developers to use the `oclhashcat_init` function to initialize a `hcapi_control` structure as a primary interface. A number of helper function pointers have been created to group the API functions, and make the code more readable. For example, rather than calling `hcapi_start` directly initializing `hcapi_control`, and calling `start_thread` will start hashcat in a background thread. 

```
hcapi_control_t hc = oclhashcat_init ();
int c;
char **v;
hc.generate_commandline (hc.options, &c, &v);
hc.start_thread (c, v);
```

The `generate_commandline` function is the core of the API. As mentioned above the API is simply constructing command line arguments (argv) to pass to the existing hashcat main function. This will allow the API to easily expand with nearly any future feature by simply adding the new switch to `generate_commandline`. 

After the variables have been set calling `generate_commandline` will run through the list of options located in `hcapi_options` structure and compare the default values with the current value set by the user. If there is a difference then a commandline argument is generated and appended to `char **` variable (passed as a parameter), and `int` (argc) is incremented. To start hashcat you can use the `start_thread` or `start` functions. `start` will start hashcat in the current thread while `start_thread` will start hashcat as a background thread.   

## Examples

### The following example shows a simple usage of the current API. This includes initialization, setting and generating parameters, starting hashcat as a background process, and retrieving status data. 

```
/* 
 * API Test Main
 *
 */
int main ()
{

  printf ("[*] Starting API Test.\n");

  hcapi_control_t hc = oclhashcat_init ();

  hc.options.attack_mode = 7;
  hc.options.markov_threshold = 32;
  hc.options.hash_input = "C:\\Users\\user\\Desktop\\hashes\\example0.hash";
  hc.options.append_dictmaskdir(&hc.options, "?a?a?a?a");
  hc.options.append_dictmaskdir (&hc.options, "C:\\Users\\user\\Desktop\\hashes\\example.dict");


  int c;
  char **v;

  hc.generate_commandline (hc.options, &c, &v);

  hc.start_thread (c, v);

  char quit = 'r';


  while (1)
  {

    quit = getchar ();
    if (quit == 'q')
    {

      hc.stop ();
      break;
    }

    if(hc.status_update (&hc.status_data)){

        
        printf("-----------------session : %s\n", hc.status_data.session);
        printf("-----------------devices_status : %u\n", hc.status_data.devices_status);
        printf("-----------------devices_status_str: %s\n", hc.status_data.devices_status_str);
        printf("-----------------hash_type : %u\n", hc.status_data.hash_type);
        printf("-----------------hash_type_str : %s\n", hc.status_data.hash_type_str);
        printf("-----------------hash_mode : %u\n", hc.status_data.hash_mode);
        printf("-----------------rp_files_cnt : %d\n", hc.status_data.rp_files_cnt);


        for(uint i = 0; i < hc.status_data.rp_files_cnt; i++)
        {

          printf("-----------------Rules file %d: %s\n", i, hc.status_data.rp_files[i]);

        }
        
        printf("-----------------rp_gen : %u\n", hc.status_data.rp_gen);
        printf("-----------------rp_gen_seed : %u\n", hc.status_data.rp_gen_seed);
        printf("-----------------input_mode : %s\n", hc.status_data.input_mode);
        printf("-----------------mask : %s\n", hc.status_data.mask);
        printf("-----------------mask_cnt: %u\n", hc.status_data.mask_cnt);
        printf("-----------------mask_pos: %u\n", hc.status_data.mask_pos);
        printf("-----------------mask_len: %u\n", hc.status_data.mask_len);
        printf("-----------------mask_len: %u\n", hc.status_data.mask_len);
        printf("-----------------start: %s\n", hc.status_data.time_started->start);
        printf("-----------------display_run: %s\n", hc.status_data.time_started->display_run);
        printf("-----------------etc: %s\n", hc.status_data.time_estimated->etc);
        printf("-----------------display_etc: %s\n", hc.status_data.time_estimated->display_etc);
        printf("-----------------devices_cnt: %u\n", hc.status_data.devices_cnt);

        for(uint device_id = 0; device_id < hc.status_data.devices_cnt; device_id++)
        {

          printf("-----------------Device %d: \n", hc.status_data.speed_dev[device_id].device_id);
          printf("-----------------\tdisplay_dev_cur: %s \n", hc.status_data.speed_dev[device_id].display_dev_cur);
          printf("-----------------\texec_all_ms: %0.2f \n", hc.status_data.speed_dev[device_id].exec_all_ms[device_id]);
          printf("-----------------\tutilization: %3u%% \n", hc.status_data.hwmon_gpu[device_id].utilization);
          printf("-----------------\ttemperature: %3uc \n", hc.status_data.hwmon_gpu[device_id].temperature);
          printf("-----------------\tfanspeed: %3uc \n", hc.status_data.hwmon_gpu[device_id].fanspeed);
          printf("-----------------\tcore: %4uMhz \n", hc.status_data.hwmon_gpu[device_id].corespeed);
          printf("-----------------\tmem: %4uMhz \n", hc.status_data.hwmon_gpu[device_id].memoryspeed);
          printf("-----------------\tlanes: %u \n", hc.status_data.hwmon_gpu[device_id].buslanes);
          printf("-----------------\tthrottle: %d \n", hc.status_data.hwmon_gpu[device_id].throttle);


        
        }

        
        printf("-----------------digests_cnt: %u\n", hc.status_data.recovered->digests_cnt);
        printf("-----------------digests_done: %u\n", hc.status_data.recovered->digests_done);
        printf("-----------------salts_cnt: %u\n", hc.status_data.recovered->salts_cnt);
        printf("-----------------salts_done: %u\n", hc.status_data.recovered->salts_done);
        printf("-----------------digests_percent: %.2f%%\n", hc.status_data.recovered->digests_percent*100);
        printf("-----------------salts_percent: %.2f%%\n", hc.status_data.recovered->salts_percent*100);

        
        printf("-----------------cpt_cur_min: %u\n", hc.status_data.recovered_time->cpt_cur_min);
        printf("-----------------cpt_cur_hour: %u\n", hc.status_data.recovered_time->cpt_cur_hour);
        printf("-----------------cpt_cur_day: %u\n", hc.status_data.recovered_time->cpt_cur_day);
        printf("-----------------cpt_avg_min: %0.2f\n", hc.status_data.recovered_time->cpt_avg_min);
        printf("-----------------cpt_avg_hour: %0.2f\n", hc.status_data.recovered_time->cpt_avg_hour);
        printf("-----------------cpt_avg_day: %0.2f\n", hc.status_data.recovered_time->cpt_avg_day);


        printf("-----------------progress_cur_relative_skip: %llu\n", hc.status_data.progress->progress_cur_relative_skip);
        printf("-----------------progress_end_relative_skip: %llu\n", hc.status_data.progress->progress_end_relative_skip);
        printf("-----------------percent_finished: %.2f%%\n", hc.status_data.progress->percent_finished*100);
        printf("-----------------percent_rejected: %.2f%%\n", hc.status_data.progress->percent_rejected*100);
        printf("-----------------all_rejected: %llu\n", hc.status_data.progress->all_rejected);

        

    } else {

      printf("ERROR status update not available\n");
    }

  }


  printf ("[!] BACK IN MAIN");

  getchar ();


  return 0;
}
```

