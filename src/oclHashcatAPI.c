/*


	Proposed oclhashcat API  prototype

	compile with:
	
	make
	
	or

	make win32API win64API


	Author: Rich Kelley
	
	Derived from oclhashcat.c
	
	Last Update: 21 March 2016

*/

#include <common.h>
#include <unistd.h>
#ifndef WIN
#include <pthread.h>
#endif

#define PW_MAX 32


struct hcapi_control;
struct hcapi_options;
struct hcapi_thread_args;

/*
	Function prototypes
*/
struct hcapi_control oclhashcat_init(void);
int hcapi_main(int, char **);
int hcapi_start(int, char **);
int hcapi_stop(void);
void hcapi_append_rules(struct hcapi_options *options, char *add);
void hcapi_append_dictmaskdir(struct hcapi_options *options, char *add);
void hcapi_generate_commandline(struct hcapi_options, int *, char ***);

#ifdef WIN
	HANDLE hcapi_start_thread(int, char **);
#else
	int hcapi_start_thread(int, char **);
#endif

void check_argv_array(char ***, size_t *, size_t *, int *);
char * strcat_ls(char *, char *);


typedef unsigned int uint;

typedef struct hcapi_thread_args {
		int c;
		char **v;

}THREAD_ARGS;

typedef struct hcapi_options 
{

	char *hash_input;


	uint  version;
	uint  quiet;
	uint  benchmark;
	uint  show;
	uint  left;
	uint  username;
	uint  remove;
	uint  remove_timer;
	uint64_t  skip;
	uint64_t  limit;
	uint  keyspace;
	uint  potfile_disable;
	uint  debug_mode;
	char *debug_file;
	char *induction_dir;
	char *outfile_check_dir;
	uint  force;
	uint  runtime;
	uint  hash_mode;
	uint  attack_mode;
	uint  markov_disable;
	uint  markov_classic;
	uint  markov_threshold;
	char *markov_hcstat;
	char *outfile;
	uint  outfile_format;
	uint  outfile_autohex;
	uint  outfile_check_timer;
	uint  restore;
	uint  restore_timer;
	uint  restore_disable;
	uint  status;
	uint  status_timer;
	uint  status_automat;
	uint  loopback;
	uint  weak_hash_threshold;
	char *session;
	uint  hex_charset;
	uint  hex_salt;
	uint  hex_wordlist;
	uint  rp_gen;
	uint  rp_gen_func_min;
	uint  rp_gen_func_max;
	uint  rp_gen_seed;
	char *rule_buf_l;
	char *rule_buf_r;
	uint  increment;
	uint  increment_min;
	uint  increment_max;
	char *cpu_affinity;
	char *opencl_devices; 
	char *opencl_platform;
	char *opencl_device_types; 
	char *truecrypt_keyfiles;
	uint  workload_profile;
	uint  kernel_accel;  
	uint  kernel_loops; 
	uint  gpu_temp_disable;
	uint  gpu_temp_abort;
	uint  gpu_temp_retain;
	uint  powertune_enable;
	uint  logfile_disable;
	uint  segment_size;
	uint  scrypt_tmto;
	char  separator;
	uint  bitmap_min;
	uint  bitmap_max;
	char *custom_charset_1;
	char *custom_charset_2;
	char *custom_charset_3;
	char *custom_charset_4;

	char *rp_files;
	void(*append_rules)(struct hcapi_options *options, char *new_file_path);

	char *dictmaskdir;
	void(*append_dictmaskdir)(struct hcapi_options *options, char *new_file_path);


}OCLHASHCAT_OPTIONS;

typedef struct hcapi_control 
{

	int(*start)(int argc, char **argvv);

#ifdef WIN
	HANDLE(*start_thread)(int argc, char **argvv);
#else
	int(*start_thread)(int argc, char **argvv);
#endif

	int(*stop)(void);
	void(*generate_commandline)(OCLHASHCAT_OPTIONS options, int *c, char ***v);
	OCLHASHCAT_OPTIONS options;

}OCLHASHCAT_CON;




char * strcat_ls(char *dst, char *src)
{
	
	size_t dst_len = snprintf(0, 0, "%s", dst);
	size_t src_len = snprintf(0, 0, "%s", src);
	size_t total_len = dst_len + src_len + 2;
	

	char *tmp = (char *)calloc(total_len, sizeof(char));

	if (tmp == NULL) {

		printf("ERROR: Allocating Memory");
		exit(1);
	}

	snprintf(tmp, total_len, "%s%s", dst, src);

	dst = tmp;
	
	tmp = NULL;
	free(tmp);
	return dst;
}

void check_argv_array(char ***apiargv, size_t *apiargv_size, size_t *apiargv_grow_by, int *apiargc)
{

	// Check if the argv array is full
	if (*apiargc == (int)*apiargv_size - 1){

		*apiargv = realloc(*apiargv, (*apiargv_size + *apiargv_grow_by) * sizeof(char*));

		// Something went wrong Free memory for apiargv
		if (*apiargv == NULL)
		{

			for (size_t i = 0; i < (size_t)*apiargc; i++)
			{
				// Free individual args
				free(*apiargv[i]);
			}

			free(*apiargv);

			printf("ERROR: Expanding Array!\n");
			exit(1);
		}

	}
}

void hcapi_generate_commandline(struct hcapi_options options, int *c, char ***v)
{
	
	/*
	 	
		Not sure if the build order matters. 
		Might need to account for positional args by building in the following order
		- options
		- hash|hashfile|hccapfile
		- dictionary|mask|directory
	
	*/
	 

	size_t apiargv_size = 1;
	size_t apiargv_grow_by = 1;
	char **apiargv = (char**)calloc(apiargv_size, sizeof(char*));
	int apiargc = 0;	

	if (apiargv == NULL)
	{
		printf("ERROR: Memory allocation failure ARGV!\n");
		exit(1);
	}

	// Account for program call
	apiargv[apiargc] = (char *)calloc(11, sizeof(char));
	apiargv[apiargc] = "oclHashcat";
	apiargc++;


	if (options.version != VERSION)
	{
		
		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(3, sizeof(char));
		apiargv[apiargc] = "-V";
		apiargc++;

	}


	if (options.quiet != QUIET)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(8, sizeof(char));
		apiargv[apiargc] = "--quiet";
		apiargc++;
		
	}


	if (options.benchmark != BENCHMARK)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(3, sizeof(char));
		apiargv[apiargc] = "-b";
		apiargc++;

	}


	if (options.show != SHOW)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(7, sizeof(char));
		apiargv[apiargc] = "--show";
		apiargc++;

	}

	if (options.left != LEFT)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(7, sizeof(char));
		apiargv[apiargc] = "--left";
		apiargc++;

	}

	if (options.username != USERNAME)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(11, sizeof(char));
		apiargv[apiargc] = "--username";
		apiargc++;

	}

	if (options.remove != REMOVE)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(9, sizeof(char));
		apiargv[apiargc] = "--remove";
		apiargc++;

	}

	if (options.remove_timer != REMOVE_TIMER)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.remove_timer)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.remove_timer);

		apiargv[apiargc] = strcat_ls("--remove-timer=", user_input);
		apiargc++;
		free(user_input);
	}

	if (options.skip != SKIP)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		int rounds = 0;
		uint64_t _result = options.skip;
		while (_result > 0)
		{

			rounds++;
			_result = _result / 10;

		}

		size_t input_size = (uint64_t)rounds + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%"PRIu64 , options.skip);

		apiargv[apiargc] = strcat_ls("--skip=", user_input);
		apiargc++;
	}

	if (options.limit != LIMIT)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		int rounds = 0;
		uint64_t _result = options.limit;
		while (_result > 0)
		{

			rounds++;
			_result = _result / 10;

		}

		
		size_t input_size = (uint64_t)rounds + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%"PRIu64, options.limit);

		apiargv[apiargc] = strcat_ls("--limit=", user_input);
		apiargc++;

	}

	if (options.keyspace != KEYSPACE)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(11, sizeof(char));
		apiargv[apiargc] = "--keyspace";
		apiargc++;

	}

	if (options.potfile_disable != POTFILE_DISABLE)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(18, sizeof(char));
		apiargv[apiargc] = "--potfile-disable";
		apiargc++;

	}

	if (options.debug_mode != DEBUG_MODE)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.debug_mode)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.debug_mode);

		apiargv[apiargc] = strcat_ls("--debug-mode=", user_input);
		apiargc++;

	}

	//str
	if (options.debug_file != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.debug_file) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.debug_file);

		apiargv[apiargc] = strcat_ls("--debug-file=", user_input);
		apiargc++;

	}

	//str
	if (options.induction_dir != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.induction_dir) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.induction_dir);

		apiargv[apiargc] = strcat_ls("--induction-dir=", user_input);
		apiargc++;

	}

	//str
	if (options.outfile_check_dir != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.outfile_check_dir) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.outfile_check_dir);

		apiargv[apiargc] = strcat_ls("--output-check-dir=", user_input);
		apiargc++;

	}

	if (options.force != FORCE)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(8, sizeof(char));
		apiargv[apiargc] = "--force";
		apiargc++;

	}

	if (options.runtime != RUNTIME)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.runtime)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.runtime);

		apiargv[apiargc] = strcat_ls("--runtime=", user_input);
		apiargc++;

	}

	if (options.hash_mode != HASH_MODE)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.hash_mode)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.hash_mode);

		apiargv[apiargc] = strcat_ls("-m ", user_input);
		apiargc++;


	}

	if (options.attack_mode != ATTACK_MODE)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.attack_mode)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.attack_mode);

		apiargv[apiargc] = strcat_ls("-a ", user_input);
		apiargc++;

	}

	if (options.markov_disable != MARKOV_DISABLE)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(17, sizeof(char));
		apiargv[apiargc] = "--markov-disable";
		apiargc++;
	}

	if (options.markov_classic != MARKOV_CLASSIC)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(17, sizeof(char));
		apiargv[apiargc] = "--markov-classic";
		apiargc++;

	}

	if (options.markov_threshold != MARKOV_THRESHOLD)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.markov_threshold)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.markov_threshold);

		apiargv[apiargc] = strcat_ls("-t ", user_input);
		apiargc++;

	}

	//str
	if (options.markov_hcstat != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.markov_hcstat) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.markov_hcstat);

		apiargv[apiargc] = strcat_ls("--markov-hcstat=", user_input);
		apiargc++;

	}

	//str
	if (options.outfile != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.outfile) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.outfile);

		apiargv[apiargc] = strcat_ls("-o ", user_input);
		apiargc++;

	}

	if (options.outfile_format != OUTFILE_FORMAT)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.outfile_format)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.outfile_format);

		apiargv[apiargc] = strcat_ls("--output-format=", user_input);
		apiargc++;

	}

	if (options.outfile_autohex != OUTFILE_AUTOHEX)
	{


		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(26, sizeof(char));
		apiargv[apiargc] = "--outfile-autohex-disable";
		apiargc++;

	}

	if (options.outfile_check_timer != OUTFILE_CHECK_TIMER)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.outfile_check_timer)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.outfile_check_timer);

		apiargv[apiargc] = strcat_ls("--outfile-check-timer=", user_input);
		apiargc++;

	}

	if (options.restore != RESTORE)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(10, sizeof(char));
		apiargv[apiargc] = "--restore";
		apiargc++;

	}


	if (options.restore_disable != RESTORE_DISABLE)
	{


		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(18, sizeof(char));
		apiargv[apiargc] = "--restore-disable";
		apiargc++;

	}

	if (options.status != STATUS)
	{


		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(9, sizeof(char));
		apiargv[apiargc] = "--status";
		apiargc++;

	}

	if (options.status_timer != STATUS_TIMER)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.status_timer)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.status_timer);

		apiargv[apiargc] = strcat_ls("--status-timer=", user_input);
		apiargc++;

	}

	if (options.status_automat != STATUS_AUTOMAT)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(17, sizeof(char));
		apiargv[apiargc] = "--status-automat";
		apiargc++;
	}

	if (options.loopback != LOOPBACK)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(11, sizeof(char));
		apiargv[apiargc] = "--loopback";
		apiargc++;
	}

	if (options.weak_hash_threshold != WEAK_HASH_THRESHOLD)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.weak_hash_threshold)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.weak_hash_threshold);

		apiargv[apiargc] = strcat_ls("--weak-hash-threshold=", user_input);
		apiargc++;

	}

	//str
	if (options.session != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.session) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.session);

		apiargv[apiargc] = strcat_ls("--session=", user_input);
		apiargc++;

	}

	if (options.hex_charset != HEX_CHARSET)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(14, sizeof(char));
		apiargv[apiargc] = "--hex-charset";
		apiargc++;

	}

	if (options.hex_salt != HEX_SALT)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(11, sizeof(char));
		apiargv[apiargc] = "--hex-salt";
		apiargc++;

	}

	if (options.hex_wordlist != HEX_WORDLIST)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(15, sizeof(char));
		apiargv[apiargc] = "--hex-wordlist";
		apiargc++;

	}

	if (options.rp_gen != RP_GEN)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.rp_gen)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.rp_gen);

		apiargv[apiargc] = strcat_ls("-g ", user_input);
		apiargc++;

	}

	if (options.rp_gen_func_min != RP_GEN_FUNC_MIN)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.rp_gen_func_min)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.rp_gen_func_min);

		apiargv[apiargc] = strcat_ls("--generate-rules-func-min=", user_input);
		apiargc++;

	}

	if (options.rp_gen_func_max != RP_GEN_FUNC_MAX)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.rp_gen_func_max)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.rp_gen_func_max);

		apiargv[apiargc] = strcat_ls("--generate-rules-func-max=", user_input);
		apiargc++;

	}

	if (options.rp_gen_seed != RP_GEN_SEED)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.rp_gen_seed)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.rp_gen_seed);

		apiargv[apiargc] = strcat_ls("--generate-rules-seed=", user_input);
		apiargc++;

	}

	//str
	if (options.rule_buf_l != (char *)RULE_BUF_L)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.rule_buf_l) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.rule_buf_l);

		apiargv[apiargc] = strcat_ls("-j ", user_input);
		apiargc++;

	}

	//str
	if (options.rule_buf_r != (char *)RULE_BUF_R)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.rule_buf_r) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.rule_buf_r);

		apiargv[apiargc] = strcat_ls("-k ", user_input);
		apiargc++;

	}

	if (options.increment != INCREMENT)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(2, sizeof(char));
		apiargv[apiargc] = "-i";
		apiargc++;

	}

	if (options.increment_min != INCREMENT_MIN)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.increment_min)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.increment_min);

		apiargv[apiargc] = strcat_ls("--increment-min=", user_input);
		apiargc++;

	}

	if (options.increment_max != INCREMENT_MAX)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.increment_max)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.increment_max);

		apiargv[apiargc] = strcat_ls("--increment-max=", user_input);
		apiargc++;

	}

	//str
	if (options.cpu_affinity != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.cpu_affinity) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.cpu_affinity);

		apiargv[apiargc] = strcat_ls("--cpu-affinity=", user_input);
		apiargc++;

	}

	//str
	if (options.opencl_devices != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.opencl_devices) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.opencl_devices);

		apiargv[apiargc] = strcat_ls("-d ", user_input);
		apiargc++;

	}
	

	//str
	if (options.opencl_platform != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.opencl_platform) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.opencl_platform);

		apiargv[apiargc] = strcat_ls("--opencl-platform=", user_input);
		apiargc++;

	}

	if (options.opencl_device_types != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.opencl_device_types) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.opencl_device_types);

		apiargv[apiargc] = strcat_ls("--opencl-device-types=", user_input);
		apiargc++;

	}

	

	//str
	if (options.truecrypt_keyfiles != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.truecrypt_keyfiles) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.truecrypt_keyfiles);

		apiargv[apiargc] = strcat_ls("--truecrypt-keyfiles=", user_input);
		apiargc++;

	}

	if (options.workload_profile != WORKLOAD_PROFILE)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.workload_profile)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.workload_profile);

		apiargv[apiargc] = strcat_ls("--workload-profile=", user_input);
		apiargc++;

	}

	if (options.kernel_accel != KERNEL_ACCEL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.kernel_accel)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.kernel_accel);

		apiargv[apiargc] = strcat_ls("-n ", user_input);
		apiargc++;

	}

	if (options.kernel_loops != KERNEL_LOOPS)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.kernel_loops)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.kernel_loops);

		apiargv[apiargc] = strcat_ls("-u ", user_input);
		apiargc++;

	}

	if (options.gpu_temp_disable != GPU_TEMP_DISABLE)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(19, sizeof(char));
		apiargv[apiargc] = "--gpu-temp-disable";
		apiargc++;

	}

	if (options.gpu_temp_abort != GPU_TEMP_ABORT)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.gpu_temp_abort)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.gpu_temp_abort);

		apiargv[apiargc] = strcat_ls("--gpu-temp-abort=", user_input);
		apiargc++;

	}

	if (options.gpu_temp_retain != GPU_TEMP_RETAIN)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.gpu_temp_retain)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.gpu_temp_retain);

		apiargv[apiargc] = strcat_ls("--gpu-temp-retain=", user_input);
		apiargc++;

	}

	if (options.powertune_enable != POWERTUNE_ENABLE)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(19, sizeof(char));
		apiargv[apiargc] = "--powertune-enable";
		apiargc++;

	}

	if (options.logfile_disable != LOGFILE_DISABLE)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
		apiargv[apiargc] = (char *)calloc(18, sizeof(char));
		apiargv[apiargc] = "--logfile-disable";
		apiargc++;
	}

	if (options.segment_size != SEGMENT_SIZE)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.segment_size)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.segment_size);

		apiargv[apiargc] = strcat_ls("-c ", user_input);
		apiargc++;

	}

	if (options.scrypt_tmto != SCRYPT_TMTO)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.scrypt_tmto)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.scrypt_tmto);

		apiargv[apiargc] = strcat_ls("-c ", user_input);
		apiargc++;

	}

	//char
	if (options.separator != SEPARATOR)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%c", options.separator);

		apiargv[apiargc] = strcat_ls("-p ", user_input);
		apiargc++;

	}

	if (options.bitmap_min != BITMAP_MIN)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.bitmap_min)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.bitmap_min);

		apiargv[apiargc] = strcat_ls("--bitmap-min=", user_input);
		apiargc++;

	}

	if (options.bitmap_max != BITMAP_MAX)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = (int)((ceil(log10(options.bitmap_max)))*sizeof(char)) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%d", options.bitmap_max);

		apiargv[apiargc] = strcat_ls("--bitmap-max=", user_input);
		apiargc++;

	}

	//str
	if (options.custom_charset_1 != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.custom_charset_1) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.custom_charset_1);

		apiargv[apiargc] = strcat_ls("-1 ", user_input);
		apiargc++;
	}


	//str
	if (options.custom_charset_2 != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.custom_charset_2) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.custom_charset_2);

		apiargv[apiargc] = strcat_ls("-2 ", user_input);
		apiargc++;
	}


	//str
	if (options.custom_charset_3 != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.custom_charset_3) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.custom_charset_3);

		apiargv[apiargc] = strcat_ls("-3 ", user_input);
		apiargc++;

	}


	//str
	if (options.custom_charset_4 != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.custom_charset_4) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.custom_charset_4);

		apiargv[apiargc] = strcat_ls("-4 ", user_input);
		apiargc++;

	}

	// This is a positional parameter
	if (options.hash_input != NULL)
	{

		check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);

		// Account for num of digits plus null
		size_t input_size = strlen(options.hash_input) + 2;

		char *user_input = (char *)calloc(input_size, sizeof(char));
		snprintf(user_input, input_size, "%s", options.hash_input);

		apiargv[apiargc] = strcat_ls("", user_input);
		apiargc++;

	}


	if (options.dictmaskdir != NULL)
	{

		char seps[] = ",";
		char *token;

		char *dictmaskdir = strcat_ls("", options.dictmaskdir);

		/**
			WARNING: strtok() is considered unsafe. Would normally us strtok_r or strtok_s,
				 but they are not standard in C99. Other options are we could roll our own, make options.dictmaskdir an char *array[] and dynamically grow for each rule, compile with 
				 -std=C11 which has strtok_r
		*/
		token = strtok(dictmaskdir, seps);

		if (token != NULL) 
		{
			while (token != NULL)
			{

				check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
				size_t input_size = strlen(token) + 2;

				char *user_input = (char *)calloc(input_size, sizeof(char));
				snprintf(user_input, input_size, "%s", token);

				apiargv[apiargc] = strcat_ls("", user_input);
				apiargc++;
				token = strtok(NULL, seps);
			}
		}
		else
		{

			check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
			size_t input_size = strlen(dictmaskdir) + 2;

			char *user_input = (char *)calloc(input_size, sizeof(char));
			snprintf(user_input, input_size, "%s", dictmaskdir);

			apiargv[apiargc] = strcat_ls("", user_input);
			apiargc++;

		}
	
	}

	if (options.rp_files != NULL)
	{

		char seps[] = ",";
		char *token;
		
		char *rule_files = strcat_ls("", options.rp_files);

		/**
			WARNING: strtok() is considered unsafe. Would normally us strtok_r or strtok_s,
				 but they are not standard in C99. Other options are we could roll our own, make options.rp_files an char *array[] and dynamically grow for each rule, compile with 
				 -std=C11 which has strtok_r
		*/
		token = strtok(rule_files, seps);

		if (token != NULL) 
		{
			while (token != NULL)
			{

				check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
				size_t input_size = strlen(token) + 2;

				char *user_input = (char *)calloc(input_size, sizeof(char));
				snprintf(user_input, input_size, "%s", token);

				/*
				 For some reason if I use "-r " (with a space) below, getopt doesn't recognize that
				 the file path/name applies to the -r switch. No idea why. 
				 I'm sure it has to do with the way I'm building apiargv. Null somewhere? Any thoughts?

				 In the mean time, going without the space seems to work in my tests. 
				*/

				apiargv[apiargc] = strcat_ls("-r", user_input);
				apiargc++;
				token = strtok(NULL, seps);
			}
		}
		else
		{

			check_argv_array(&apiargv, &apiargv_size, &apiargv_grow_by, &apiargc);
			size_t input_size = strlen(rule_files) + 2;

			char *user_input = (char *)calloc(input_size, sizeof(char));
			snprintf(user_input, input_size, "%s", rule_files);

			/*
				 For some reason if I use "-r " (with a space) below, getopt doesn't recognize that
				 the file path/name applies to the -r switch. No idea why. 
				 I'm sure it has to do with the way I'm building apiargv. Null somewhere? Any thoughts?

				 In the mean time, going without the space seems to work in my tests. 
			*/
			apiargv[apiargc] = strcat_ls("-r", user_input);
			apiargc++;

		}
	
	}

	
	*c = apiargc;
	*v = apiargv;

	return;
}

int hcapi_start(int argc, char **argv)
{

	printf("[+] Start Called \n");
	int rtcode;

	printf("argc = %d\n", argc);
	printf("argv = ");

	for (int i = 0; i < argc; i++)
	{
		printf("%s ", argv[i]);
	}

	rtcode = hcapi_main(argc, argv);

	return rtcode;
}

#ifdef WIN
unsigned __stdcall start_hc_thread(void *params){

	THREAD_ARGS *args = (THREAD_ARGS*)params;

	int argc = args->c;
	char **argv = args->v;

	printf("argc = %d\n", argc);
	printf("argv = ");

	for (int i = 0; i < argc; i++)
	{
		printf("%s ", argv[i]);
	}
	printf("\n");

	printf("[+] Start Thread Called from Thread: %lu \n", GetCurrentThreadId());
	hcapi_main(argc, argv);


	return 0;
}

HANDLE hcapi_start_thread(int argc, char **argv)
{

	HANDLE hThread;
	unsigned int threadID;

	THREAD_ARGS args;
	args.c = argc;
	args.v = argv;


	printf("[+] Calling thread \n");
	hThread = (HANDLE)_beginthreadex(0, 0, &start_hc_thread, &args, 0, &threadID);
	sleep(1);

	return hThread;
}
#else

void * start_hc_thread(void *params){

	THREAD_ARGS *args = (THREAD_ARGS*)params;

	int argc = args->c;
	char **argv = args->v;

	
	pthread_t self;
	self = pthread_self();

	printf("[+] Start Thread Called from Thread: %d \n", (int)self);
	hcapi_main(argc, argv);


	return NULL;
}

int hcapi_start_thread(int argc, char **argv)
{

	int err;
	pthread_t hThread;
	THREAD_ARGS args;
	args.c = argc;
	args.v = argv;

	err = pthread_create(&hThread, NULL, &start_hc_thread, &args);
	sleep(1);
	
	printf("\n[!] thread returning with %d \n", err);
	return err;
	
}
#endif


int hcapi_stop(void)
{

	printf("[+] Stop Called.\n");
	return 0;
}

void hcapi_append_rules(struct hcapi_options *options, char *new_file_path)
{

	printf("[+] Called Append Rules.\n");

	if (options->rp_files != NULL)
	{
    			
		options->rp_files = strcat_ls(options->rp_files, ",");
		options->rp_files = strcat_ls(options->rp_files, new_file_path);

	} 
	else
	{
		options->rp_files = new_file_path;
	}


	return;
}

void hcapi_append_dictmaskdir(struct hcapi_options *options, char *new_file_path)
{

	printf("[+] Called Append Dict, Mask, or Dir.\n");

	if (options->dictmaskdir != NULL)
	{
    			
		options->dictmaskdir = strcat_ls(options->dictmaskdir, ",");
		options->dictmaskdir = strcat_ls(options->dictmaskdir, new_file_path);

	} 
	else
	{
		options->dictmaskdir= new_file_path;
	}


	return;
}

OCLHASHCAT_CON oclhashcat_init(void)
{

	printf("[+] Intializing\n");

	OCLHASHCAT_CON control;

	control.options.hash_input = NULL; 			// positional param --> hash|hashfile|hccapfile
	control.options.dictmaskdir = NULL;			// positional param --> [dictionary|mask|directory]


	control.options.version = VERSION;
	control.options.quiet = QUIET;
	control.options.benchmark = BENCHMARK;
	control.options.show = SHOW;
	control.options.left = LEFT;
	control.options.username = USERNAME;
	control.options.remove = REMOVE;
	control.options.remove_timer = REMOVE_TIMER;
	control.options.skip = SKIP;
	control.options.limit = LIMIT;
	control.options.keyspace = KEYSPACE;
	control.options.potfile_disable = POTFILE_DISABLE;
	control.options.debug_mode = DEBUG_MODE;
	control.options.debug_file = NULL;
	control.options.induction_dir = NULL;
	control.options.outfile_check_dir = NULL;
	control.options.force = FORCE;
	control.options.runtime = RUNTIME;
	control.options.hash_mode = HASH_MODE;
	control.options.attack_mode = ATTACK_MODE;
	control.options.markov_disable = MARKOV_DISABLE;
	control.options.markov_classic = MARKOV_CLASSIC;
	control.options.markov_threshold = MARKOV_THRESHOLD;
	control.options.markov_hcstat = NULL;
	control.options.outfile = NULL;
	control.options.outfile_format = OUTFILE_FORMAT;
	control.options.outfile_autohex = OUTFILE_AUTOHEX;
	control.options.outfile_check_timer = OUTFILE_CHECK_TIMER;
	control.options.restore = RESTORE;
	control.options.restore_timer = RESTORE_TIMER;
	control.options.restore_disable = RESTORE_DISABLE;
	control.options.status = STATUS;
	control.options.status_timer = STATUS_TIMER;
	control.options.status_automat = STATUS_AUTOMAT;
	control.options.loopback = LOOPBACK;
	control.options.weak_hash_threshold = WEAK_HASH_THRESHOLD;
	control.options.session = NULL;
	control.options.hex_charset = HEX_CHARSET;
	control.options.hex_salt = HEX_SALT;
	control.options.hex_wordlist = HEX_WORDLIST;
	control.options.rp_gen = RP_GEN;
	control.options.rp_gen_func_min = RP_GEN_FUNC_MIN;
	control.options.rp_gen_func_max = RP_GEN_FUNC_MAX;
	control.options.rp_gen_seed = RP_GEN_SEED;
	control.options.rule_buf_l = (char *)RULE_BUF_L;
	control.options.rule_buf_r = (char *)RULE_BUF_R;
	control.options.increment = INCREMENT;
	control.options.increment_min = INCREMENT_MIN;
	control.options.increment_max = INCREMENT_MAX;
	control.options.cpu_affinity = NULL;
	control.options.opencl_devices = NULL;
	control.options.opencl_platform = NULL;
	control.options.opencl_device_types = NULL;
	control.options.truecrypt_keyfiles = NULL;
	control.options.workload_profile = WORKLOAD_PROFILE;
	control.options.kernel_accel = KERNEL_ACCEL;
	control.options.kernel_loops = KERNEL_LOOPS;
	control.options.gpu_temp_disable = GPU_TEMP_DISABLE;
	control.options.gpu_temp_abort = GPU_TEMP_ABORT;
	control.options.gpu_temp_retain = GPU_TEMP_RETAIN;
	control.options.powertune_enable = POWERTUNE_ENABLE;
	control.options.logfile_disable = LOGFILE_DISABLE;
	control.options.segment_size = SEGMENT_SIZE;
	control.options.scrypt_tmto = SCRYPT_TMTO;
	control.options.separator = SEPARATOR;
	control.options.bitmap_min = BITMAP_MIN;
	control.options.bitmap_max = BITMAP_MAX;
	control.options.custom_charset_1 = NULL;
	control.options.custom_charset_2 = NULL;
	control.options.custom_charset_3 = NULL;
	control.options.custom_charset_4 = NULL;
	control.options.append_rules = hcapi_append_rules;
	control.options.append_dictmaskdir = hcapi_append_dictmaskdir;
	control.options.rp_files = NULL;

	control.start = hcapi_start;
	control.start_thread = hcapi_start_thread;
	control.stop = hcapi_stop;
	control.generate_commandline = hcapi_generate_commandline;
	
	return control;

}


/*
* API Test Main
*
*/
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

	// Lots of prints for testing. To be deleted upon release
	printf("[!] BACK IN MAIN");
	getchar();
	

	return 0;
}
