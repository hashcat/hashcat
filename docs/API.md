This document serves as a temporary guide to the notional oclHashcat API. The intent is show other potential developers the current direction of the API, and to get them up-to-speed to help with development of the API itself. The idea is for this to be replaced by a complete API reference once completed. 


Basic concept:
--------------

Fundamentally the API is simply constructing command line arguments (argv) to pass to the existing oclHashcat main function. The arguments are constructed by comparing the default value of a variable to the currently assigned value. If there is a change then the command is added to the argv array. 

The core of the API is located in the src/oclHashcatAPI.c source file, but there are also minor addition/edit to oclHashcat.c 

Compiling:
---------------

When using the API use the -DAPI compiler flag. This is already included in the Make file. For testing purposes you only have to type

    make win64API win32API linux64API linux32API


Functions:
----------

    struct hcapi_control oclhashcat_init(void);

Function to initialize a useful API data structure - hcapi_control, which is explained below. The intent is for this to be the first function called when accessing the API

**None of the following functions are intended to be called directly. Instead the intent is to interface through function pointers within the hcapi_control structure. Although there is nothing stopping a developer from using these function directly should they choose to.**

    int hcapi_main(int, char **);

When the -DAPI compiler flag is used this becomes the new entry to point to the main oclHashcat code path. In other words, this used to the main().

    int hcapi_start(int, char **);

Wrapper to pass command line arguments to the hcapi_main function.
	
    int hcapi_stop(void);

(TODO) Stop oclHashcat process.

    void hcapi_append_rules(struct hcapi_options *options, char *add);

Builds a comma separated list of paths to files containing rules.

    void hcapi_append_dictmaskdir(struct hcapi_options *options, char *add);

Builds a comma separated list of paths/strings to files or directories containing dictionaries, masks or other positional input.

    void hcapi_generate_commandline(struct hcapi_options, int *, char ***);
	
Compares the default parameter values to the currently assigned values. Any delta is appended and stored in the argv parameter (char ***)

    void check_argv_array(char ***, size_t *, size_t *, int *);

Internal function to check the size of the argv array and expand as needed.

    char * strcat_ls(char *, char *);

String concatenation function

    HANDLE hcapi_start_thread(int, char **);

Starts oclHashcat in a background thread (WIN)

    int hcapi_start_thread(int, char **);

Starts oclHashcat in a background thread (POSIX)

Data Structures:
----------------

    struct hcapi_control;

This structure is returned by the oclhashcat_init() function, and provides the following convienance functions controlling oclHashcat programmatically

  start, stop, generate_commandline, get_data, start_thread
  
  Ex: 
  OCLHASHCAT_CON hc = oclhashcat_init();
  hc.start() // see below for a more complete example
  hc.stop() 
  
  
    struct hcapi_options;
  
This structure holds all the various command line variables for oclHashcat. Each option can be accessed/assigned via the dot operator

    hc.options.attack_mode = 0;
  	hc.options.hash_mode = 1000;
  	hc.options.hash_input = "C:\\Users\\auser\\Desktop\\hashes.txt";
  
    struct hcapi_thread_args;

This structure is used by hcapi_start_thread to pass multiple args to the thread creation functions. 



Example:
--------

    int main()
    {
    
    	printf("[*] Starting API Test.\n");
    
    	OCLHASHCAT_CON hc = oclhashcat_init();
    
    
    	hc.options.attack_mode = 0;
    	hc.options.hash_mode = 1000;
    	hc.options.hash_input = "C:\\Users\\auser\\Desktop\\hashes.txt";
    	hc.options.append_dictmaskdir(&hc.options, "C:\\Users\\auser\\Desktop\\Dicts\\dictionary.txt");
    	hc.options.append_rules(&hc.options, "C:\\Users\\auser\\Desktop\\Rules\\somerulse.rule");
    	hc.options.append_rules(&hc.options, "rules\\best64.rule");
    	
    	hc.options.quiet = 1;
    
    	int c;
    	char **v;
    
    	
    	hc.generate_commandline(hc.options, &c, &v);
    
    	// start_thread works for either win or linux systems
    	// alternatively you can just call start() in a similar way to call in the same thread
    	hc.start_thread(c, v);
    
    
    	// get_data currently returns a pointer to data structure in oclHashcat.c
    	// As of right now there is no mutex keeping one thread from currupting the other
    	// I'm also not sure of the performance impact of reading from this while oclhashcat is working
    	// This needs to be handled better
    	hc_global_data_t *output = malloc(sizeof(hc_global_data_t));
    	output = hc.get_data(); 
    
      // Output example. NOTE get_data() needs A LOT of work to be safe and not cause performance problems with oclHashcat
    	printf("install dir: %s", output->install_dir);
    
    	getchar();
    	
    
    	return 0;
    }
