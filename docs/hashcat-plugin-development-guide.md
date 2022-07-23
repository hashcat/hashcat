# Hashcat Plugin Development Guide #

The purpose of this document is to introduce you to the development of plugins for hashcat 6.0.0 and newer. We will update this document regularly and add more detailed content. The content in its current state includes enough details to write easy, medium and hard plugins.

With hashcat 6.0.0, a new interface has been designed which enables you to add new hash-modes more easily than in older hashcat versions. The plugin interface is an essential new feature of hashcat 6.0.0.

One of our goals was to have the new interface to be independent from future versions of hashcat. This is achieved by hashcat loading your plugin code dynamically from a .so/.dll/.dylib library on startup. Another goal was to give the author of the plugin the option to share the plugin as source or in binary form. This is achieved by a clear separation between hashcat core code and plugin code. There is no longer a need to change hashcat core sources in order to add a new hash-mode. All existing hash-modes (300+) from older hashcat versions have been refactored to this new interface.

We are well aware that as a developer you want to see as little change as possible on this interface. That is why our third goal was to get the interface to a fairly final state and minimize the risk of changing it once it is released. That is not an easy task. When you are designing such an interface, there is always a chance that you are missing some details for rare use cases. The refactorization of the 300+ existing hash-modes served both as a reference check and a feasibility study. We do not plan to change the interface except if there is a strong need for it. For that unlikely event of a major change, there is an automatic version check which is added automatically to your module at compile time.

To make kernel development as easy as possible, we have already started in previous hashcat versions to include GPU-optimized OpenSSL-like crypto interfaces and finalized it with hashcat 6.0.0. If you are familiar with that interface, you know it typically uses a chain of context init(), update() and final() function calls. In all refactored pure kernel sources, you can see this interface type design being used. It is also our hope that the structure of the well known interface will make it easy for developers to use the existing kernel source as a useful reference.

Developing a hashcat plugin can be very overwhelming at first. Do not get discouraged by it. After the first plugin, you will already feel practiced - and you will soon realize that the development steps are always the same.

## Plugin Structure ##

Let us jump right in. To develop a plugin for hashcat, you basically just need to create two files:

* Module: This is where you do all the initial hash-mode configuration work. It is the code which executes on the CPU of the host system. Note that we are not talking about the compute-intense crypto stuff. For instance, the module is responsible for decoding of the hash file entries and to copy the data to the standardized hashcat memory structures. It features many different functions which you can use for special handling of your hash file data. You can choose much easier the rich library for decoding, encoding and converting you want to use. The modules are stored in the folder `src/modules/`.
* Kernel: This is the place where you put the real crypto implementation of your hash mode. This is the time-consuming code which is executed on the compute devices. The kernels are stored in the folder `OpenCL/`. Note that CUDA kernels also will be stored in that folder and have a .cl filename suffix. This may change in the future.

You will read the terms "module" and "kernel" quite often from now on. Just for terminology, the combination of both "module" and "kernel" is what we call a hashcat "plugin".

There is an -optional- third file: The unit-test stub. In this file you can implement the crypto scheme of your hash-mode from a "high-level" perspective. The stub is then called from hashcat's own testing suite. The goal is to test your hashcat plugin implementation by comparing the results of the unit-test stub with the results created from hashcat itself while using your plugin. It will automatically generate random passwords, salts, hashes, etc. for you and compare everything in very deep detail - so you can be sure your plugin implementation works in all different attack modes and most importantly also in some corner cases that might exist.

## Before the code ##

You need to code in the C language. If you are a C beginner, this may be a bit too hard, but if you have programming skills in C or if you have crypto programming skills in a different programming language, you should be able to write a hashcat plugin. While you have this documentation as a reference, it won't give you all the information (rarely used module functions or kernel function etc) you need. Be prepared to study existing code from other plugins for information.

Rule number one: It is pointless to start developing a plugin if you do not have a deep understanding of the algorithm which you want to implement. Writing a plugin is a multi-layered process which you have to approach step by step. You never write the plugin from start to finish in a giant leap. Since we are working on a very low level, there is a big need for small milestones where you can stop and control intermediate values. For instance, if you want to implement a hash-mode which does md5(sha1($p)), then you implement sha1($p) first. At this point it makes sense to add a milestone to control the intermediate hash before you continue implementing the md5(). But where do you get these intermediate control values from? The answer is simple: from proof-of-concept code which you already have or write yourself first. It does not matter which language that this POC is written in, as long as you know how to breakpoint or how to manipulate the POC in order to print the wanted intermediate values.

One more thing. You need to make an essential decision before you start with your implementation. You need to categorize your algorithm beforehand. Based on the details of the algorithm, it is either a so-called "fast" or a "slow" kernel type. This decision cannot be changed easily afterwards, so take your time. Do not worry, the right answer to this decision is simple and you can derive it from some algorithm details.

Rule of thumb:

* More than 100 iterations from whatever crypto primitive? -> slow kernel
* Expected less than 10 million guesses per second per GPU? -> slow kernel

Otherwise you probably want to develop a "fast" kernel. Note that the most crypto primitives that would need to be implemented as a fast kernel already are implemented. However, if you actually want to write a "fast" kernel the main goal is to workaround the PCI Express bottleneck. For a more detailed explanation on how to calculate the bandwidth please have a look here: https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#does_the_pci-express_speed_have_any_influence_on_cracking_speed. To workaround this bottleneck, you need to write attack-mode specific kernels. These kernels have a very special structure, but from a development perspective you just write your code in a "block" inside another level of a for() loop, the remaining parts are similar to what is used in a typical slow kernel.

However, I expect most people reading this document want to write a "slow" kernel. Luckily, writing a slow kernel is easier to start with. Most of the time, you will find the compute-intense code in a kernel you can copy/paste from other kernels or the GPU crypto library and it is just for the final comparison/verification that you need to put in some brain power.

Another preparation you need to make before you start coding is to pick the right hash-mode number. To make it short, there is some logic to this, but it is not easy to explain.

* If you do not want to push your code to hashcat upstream, simply pick a number between 90000 and 100000. We will not use this range in the upstream repository. This way we can avoid any collisions in the numbering system.
* If you plan to contribute your code to hashcat upstream, please follow these guidelines: Think in steps of 100's, so that your hash-mode ends with 00. Go to hashcat GitHub master and check for the highest hash-mode being used (For example, see src/modules/). Select a number by yourself which ends with 00 and that is a number which is between 1000 and 2000 higher than the current highest existing hash-mode. For instance, if the highest value is 21500, then a valid hash-mode number for your plugin could be 22800. The moment when you PR your code, we will reserve a fixed hash-mode number for you. The changes afterwards will cost only a few minutes of time.

## Development Environment ##

In theory there is no special hardware required for hashcat plugin development. However, there are some recommendations that we can give you:

* Stick as close as possible to the hardware on which the plugin is supposed to run on. For instance, If you write a plugin which is supposed to be used by pentesters (like Kerberos), you probably want to use a mobile GPU for development. If you write a plugin which is probably used on private computers (like crypto-currency wallets), use a discrete mid-range GPU. If you write a plugin being used in digital forensics (like TC), you probably want to use a discrete high-end GPU.
* If you plan to use an NVIDIA GPU you will have the least unwanted side effects. Additionally this has the advantage you can test it on both the new CUDA and the old OpenCL backend. Since hashcat version 6.0.0 there is a backend which supports both compute API. Note that you will need to install the CUDA SDK in case you want to use the CUDA backend. The CUDA SDK is required for both developing and running CUDA kernels. This goes back to the problem that the NVIDIA driver does not support JIT compiling the kernels. That is the advantage of OpenCL over CUDA. You only need the drivers and the ICD installed.
* If you plan to use an AMD GPU, please use ROCm drivers. This limits you to use Linux. At the time of writing this document, the use of amdgpu-pro drivers is a pain. Do yourself a favor and do not try to develop on amdgpu-pro drivers.
* If you plan to use a CPU for development, make sure that you install and use the Intel OpenCL Runtime. Interestingly, even if you are using an AMD CPU, the Intel runtime runs very smoothly with them. Do not try to use MESA, POCL or Beignet/NEO drivers. Also note that on a CPU there is no such thing like shared memory that we have on GPUs. If your algorithm is making heavy use of shared memory you will not see the effects of it.

One of the most important factors for choosing the right compute API is that it supports using printf() from inside the kernel. In the past this way of debugging was not possible, which made kernel development a real pain. With the current OpenCL drivers this works pretty well. Get used to the idea that printf() becomes your primary debugging utility. Since you only write a very small piece of code in the kernel it is not as bad as you may think.

Personally, I like to write my plugins on Linux, but of course you can also use macOS or Windows. All regular runtimes support debugging functionalities on all operating systems.

Some more remarks for the hardware of your development platform:

* Since you will recompile the kernel (via the JiT) very often. To avoid getting frustrated waiting for the compiler to finish, I think it is very beneficial to have a high clocked CPU. The number of cores is not very important (for development system).
* Limit the system to a single GPU only. Otherwise the code is compiled for each GPU in the system. While the code is cached after the same GPU types, the memory allocation can not. Each additional GPU will significantly increase your startup time. Start on a single GPU, then switch to a multi GPU system at a later point in time.
* High-End GPUs can have a negative effect on development since they ship with a lot of specialized hardware instructions. Since the JiT will always try to optimize your code as much as possible, these additional instructions will complicate the optimizers task.
* Low-END GPUs can have a negative effect on development since they lack resources. You will maybe write your code in a too resource saving way, hurting the performance on a High-End GPUs.

My Development at the time of writing this document (beginning of 2020) is an Intel I5 generation 6 with a regular SSD and 16GB memory. The system runs on Ubuntu 18.04 Server. The GPU is an NVIDIA GTX 980. Additionally I am using Intel OpenCL runtime, but only to test the code on the CPU afterwards.

Before you actually start with your implementation make sure you have already cloned hashcat from GitHub master, that you are able to compile it on your system and that it runs smoothly. Make sure you have a clean installation with no previous version artifacts laying around.

## Test Suite ##

The optional unit-test stub originally was made only to automate the task of plugin verification. It is written intentionally in a different language (Perl) and not in C. From our perspective this has a lot of advantages and benefits. Despite of the language the input and the output data of any hashing/encryption algorithm should be the same. If they match, then your plugin implementation is very likely to be working correctly.

From our experience in the last years adding new hashcat hash-modes we cannot stress enough how important it is to have a POC (as described earlier) to print intermediate values. If we do not already have some sort of POC, we use this optional unit-test stub as a POC replacement. Writing a unit-test is typically done from a high-level programming language, thus Perl is a good candidate to do so, but there is also some unit-test stubs written in python. At this point we already created some synergy because you can use it as a POC to start with the development and later it acts as a normal unit-test stub and you do not have to write it twice. If you do not care about POC's and unit-test you can directly jump to the module subsection from here.

The Test Suite is a Perl Framework. The main program (tools/test.pl) loads at runtime the hash-mode specific code written like a plugin. The structure of this perl module is standardized. We have already mentioned that all existing code to the 300+ hash-modes from previous hashcat versions have been refactored. Also all 300+ hash-mode specific unit-test stubs have been refactored into this new Test Suite Framework. The same way the before mentioned modules and kernels act as a reference, the unit-test stubs can also be used as reference. In most of the cases you can simply copy/paste from an existing unit-test stubs, change a small piece of code and both are ready, the POC and the unit-test stub.

The test suite itself consists of two files:

* tools/test.pl: This program generates random passwords, salts and loads the unit-test stub code which you will develop.
* tools/test.sh: This script compares the generated passwords from test.pl with the output from hashcat. It calls the hashcat binary multiple times, each time with a different set options to test your implementation on a deep level.

The filename of your unit-test stub has to be: tools/test_modules/m[hash_mode].pm

### test.pl ###

The tools/test.pl Script has three different use cases:

* Single (default)
* Passthrough
* Verify

When calling tools/test.pl from the command line, the first parameter you have to give is the use case type. It should be either "single", "passthrough" or "verify".

You need to implement three methods in your unit test stub. Note that the use cases are not directly related to the methods. You need to implement all three, then you can make use of all three use cases:

* module_constraints()
* module_generate_hash()
* module_verify_hash()

The second parameter is the hash-mode itself. In case of "verify" you have to give some additional parameters. For the exact syntax please see `tools/test.pl --help`.

In order to get `tools/test.pl` running you need to install a lot of perl modules. To help you install them quickly, we have developed a simple script `tools/install_modules.sh`. You may want to take a look inside before you execute it. At this time, none of the perl modules require a special version which means you can also use the perl modules which your distribution offers to you (if you prefer it that way, for instance the GCrypt perl module with `apt install libcrypt-gcrypt-perl` on Debian/Ubuntu).

#### Single Mode ####

In single mode, a number of random passwords are generated for the selected hash mode. Each of the generated passwords is passed to the module_generate_hash() method (which is one of the methods you have to populate with code) and thus a hash is generated. In the end, both information, password and final hash line (which typically also contains the salt) are output to stdout, so that you can execute the output as if it would be a real shell script. If your hash-mode requires one (or more) salts, this will also be created automatically. The most important thing is that test.pl generates passwords of different lengths, with the guarantee that the minimum and maximum length password are always included.

Attention: The testing suite expects that the module_generate_hash() method will return the output of the final hash line. You have to return this as a string in the exact format that hashcat will later accept.

If your implementation contains optimizations based on the password length (for example 0x80's, zero based options, etc.) then you would also want to verify that such optimizations also work with all possible password lengths. Therefore, another function must exist in your stub: module_constraints().

The module_constraints() method is easy to understand. It returns exactly 5 integer pairs. These pairs always define a range, therefore they consist of a minimum and a maximum number. The order of the pairs is the following:

* Pure-Mode-PW-Constraints
* Pure-Mode-Salt-Constraints
* Optimized-Mode-PW-Constraints
* Optimized-Mode-Salt-Constraints
* Optimized-Combined-PW-and-Salt-Constraints

If you do not need one of the named pairs or the pair does not make sense because it is not applicable, you must use -1 for minimum and maximum. Please note that there is a strong difference between pure and optimized kernels. We have not discussed this concept so far, therefore let us stick to pure kernels. With a few exceptions, slow hash types have no implementation of an optimized mode, because the performance does not drop too much because of register pressure, but because of the iteration count, which you cannot optimize. We will come to the different kernel modes in the kernel section.

Another important note about salts. Often one or more salts are needed. Possible iteration counts, IV or random content data can also be seen here as "salt". This data can be so different that it does not fit into a single policy / interface. Therefore, test.pl cannot standardize this complex situation. For simple forms of salts only, test.pl provides you with a simple form of random salt data. You can specify the length constraints (min/max) of the salt data in the constraints section. In more complex situations, you will not be able to avoid creating your own salts by calling some helper functions that test.pl provides you with, directly in the module_generate_hash() method.

Example:

```
my $iter      = shift // 10000;
my $user_salt = shift // random_hex_string (128)
my $ck_salt   = shift // random_hex_string (128)
my $user_iv   = shift // random_hex_string (32)
```

#### Passthrough Mode #####

In passthrough mode, test.pl expects the *passwords* from you, quite the opposite of single mode where they were generated automatically. Every password that you send via stdin (e.g. pipe) is passed to the module_generate_hash() method and the resulting hash is sent to stdout. The rest is identical to single mode.

Example:

```
$ echo hashcat | tools/test.pl passthrough 1600
$apr1$93341$gNT2pItX5h6Lc/XjTWuyb1
```

Note: In this specific case the newline character after the password (compare it to `echo -n hashcat`) is used as a delimiter between the lines/passwords and therefore not considered part of the password (remember that `echo hashcat | md5sum` for instance produces "wrong" results, in general, because of the extra newline).

#### Verify Mode #####

In verify mode you go one step further than in single or in passthrough mode. In two different files you give both, a specific hash and in another file the (same) hash including the matching password. The goal is that the expected hash is generated from the module_generate_hash() method, which is then compared with the input from the first file. If the comparison passed, the original hash is written in a third file.

This is where the module_verify_hash() method is used for the first time. In this method, you have to break down the hash line into its individual parts, especially those components that are absolutely necessary to reconstruct the exact same hash. For instance, if the algorithm needs one or more salts, then this salt must be extracted. Finally you call the module_generate_hash() using the extracted components (salts, iteration counts etc).

At this point we need to go back to the module_generate_hash() function. To make the verification work. It is necessary that your module_generate_hash() function recognizes whether a salt has been newly generated and, if this is the case, only then actually generate a random salt yourself (as described in the single mode).

Here is a real life example from Android Backup plugin (tools/test_modules/m18900.pm)

```
sub module_generate_hash
{
  my $masterkey_blob = shift;
  ...
  if (defined $masterkey_blob)
  {
    # verify call, write code to use the given salt
  }
  else
  {
    # regular call, write code to generate random salt
  }
  ...
```

The script is called with the following command line parameters:

```
perl tools/test.pl verify 18900 hash_list.txt cracked_list.txt verified_list.txt
```

After the command line parameter "verify" the hash mode is specified ("18900" in this example), followed by the original hash list (hash_list.txt) without passwords. After the hashfile the path of the file with the list of cracked hashes, including passwords is given. The format of this file is simply hash[:salt]:password the same way as hashcat would output them. Note that you can have multiple lines. The third parameter specifies the output file. It contains the lines that have been verified as correct and that also appear in the original hash list.

You should also always test that the exit code of test.pl is 0, otherwise it could be that the output file was not overwritten.

The verify mode is an excellent replacement for a missing POC.

### test.sh ###

The test.sh is an overlay for test.pl, which actually calls the hashcat binary based on the return values from test.pl in single mode (it interacts with both). The test.sh shell script also compares the return values of the hashcat binary with the expected result. This includes tests such as whether all hashes have been cracked, whether the associated password is the correct one and not any other from the test.pl return, whether the output hash is displayed in the correct format, etc.

Furthermore, the script has many different options (when called in the command line) with which you can narrow down to specific tests. You typically want to make use of this feature, because a complete test run across all hash modes can take several days.

The main options:

* Select hash type (-m): Test only a special hash-mode
* Select test mode (-t): Test either single-hash or multi-hash kernel
* Select attack mode (-a): Test a special attack mode. With a slow hash, this is automatically switches to a straight attack, because there are no attack-mode specific kernel implementations

If the options are not set, attack-mode 0 for hash-mode 0 is executed. To see additional options, see tools/test.sh --help




## Module ##

The first really needed ingredient to create a plugin is the module. The module is a single .c source code file in which you can freely implement the 68 different interface functions or add your own auxiliary functions. No worries, I have never had a module which required me to implement all 68 functions. Many functions are really only required in special cases. In the best cast you only need to implement 2 functions.

The integration in hashcat is very easy. Your module is compiled to a .so shared object on Linux (or .dll on Windows and .dylib on macOS). The moment when hashcat starts, it loads the shared object corresponding to the hashmode the user specified by the -m option (default is -m 0).

The path in which you have to store your module is `src/modules/module_XXXXX.c`. From there the module is compiled as a shared object into the folder `$(SHARED_FOLDER)/modules/module_XXXXX.[so|dll|dylib]`. The XXXXX is the hash-mode number (with leading zeros). There is no need to adjust any hashcat core sources. The makefile `src/Makefile` automatically finds the module you added and compiles it with the necessary flags.

If you run hashcat under linux or macOS without the `make install` target from the current working directory, then `$SHARED_FOLDER` typically equals the current working directory. On Windows it is always the current working directory because there is no install target in the makefile. A modification of the Makefile is probably only necessary in exceptional cases, i.e. if your module requires an external library. In this case and if you want to contribute the plugin to upstream, then we have to coordinate the development. Please contact us directly in such cases.

There is no need to implement any black magic into the module. A module covers exactly what you would expect from plugin, which is this:

* Attack type (fast hash or slow hash)
* Digest size and orderings
* Salt type
* Hash name and category
* Kernel number
* Various optimizers and workflow options
* Hash and Password for self-test purpose
* Decoder and Encoder
* Password and Salt length limits
* Hook functions
* JiT compiler options

Namely, these configurations take place in a variety of optional functions that you provide in every module. There are a few mandatory functions which need to be implemented:

* module_init()
* module_hash_decode()
* module_hash_encode()
* module_attack_exec()
* module_dgst_pos0()
* module_dgst_pos1()
* module_dgst_pos2()
* module_dgst_pos3()
* module_dgst_size()
* module_hash_category()
* module_hash_name()
* module_kern_type()
* module_opti_type()
* module_opts_type()
* module_salt_type()
* module_st_hash()
* module_st_pass()

At first glance, this looks a bit overwhelming. But in fact, all of these functions (apart from the first three) are only configuration parameters. You may wonder why we have not designed the module by simply setting a macro/number item for each of the configurations. But we wanted to give you the opportunity to change this configuration at runtime and not just at compile time. For example, if you only want to use a specific optimizer but only if the user runs the kernel on a GPU and not if the user runs it on a CPU. But this actually goes into deep detail. In reality, it usually looks like this:

```
static const char *HASH_NAME = "MD5";
...
const char *module_hash_name (...) { return HASH_NAME; }
...
module_ctx->module_hash_name = module_hash_name;
```

As you can see here, there is a so-called module_ctx object. Here you register all functions that you have implemented in your module and which should be used by hashcat. A list of all functions and their prototypes can be found under `include/modules.h`.

Hashcat will automatically call the module_init() function when it loads your module. In this function, you simply register all the functions that you have programmed by assigning it to module_ctx.

Example:

```
module_ctx->module_hash_name = module_hash_name;
```

For all functions that you do not use, please use the macro MODULE_DEFAULT. Using this macro, hashcat can see that its module_ctx_t structure is in the correct version (if you only want to distribute a binary). For instance, if a new function is added in a future version, the structure in the binary-distributed older version is one address too short and contains the value NULL. With this approach, hashcat can ensure that you work with your compatible module_ctx_t structure.

The only two mandatory functions that you normally have to program for a minimal plugin integration, are the decoder function module_hash_decode() and the encoder function module_hash_encode(). The other remaining mandatory function which typically only consists of static configuration items, but not code. Here is each of them explained:

### module_attack_exec() ###

There are only two different types that have already been discussed in the "Before the code" chapter. Here you determine whether your kernel is slow or fast hash.

* ATTACK_EXEC_OUTSIDE_KERNEL -> slow hash
* ATTACK_EXEC_INSIDE_KERNEL  -> fast hash

The naming goes back to how the password candidate generator was implemented in the past. If the hash is a slow hash, reading a password candidate from GPU memory does not have any relevant impact on the performance. Therefore we can execute the password candidate generator in a standalone kernel and call it beforehand (there are actually three: STRAIGHT, COMBINATOR, MASK). The kernel then writes the resulting candidates to GPU memory. After that, hashcat calls the hash-type specific _init kernel function which loads the candidates from GPU memory.

If the crypto of the kernel is very fast, reading from GPU memory would create a bottleneck. For fast hashes we need a different approach. We load a "base" passwords from GPU memory to GPU registers, but only at the start of the kernel, in the "outer" loop. Then we enter an inner loop inside the kernel in which we iterate through a (limited) number of modifications and apply them to the base word. Note: this is what we call the kernel-loops. We can modify the candidate on a register level which keeps the memory access very low. In hashcat we have three base attack modes (STRAIGHT, COMBINATOR, MASK), for each of which we need to implement a specific kernel. The only difference is how we apply the modification on the base password candidate.

I will explain more about the details in the kernel section, but this already explains why writing a slow hash kernel is much easier. It is just one kernel, not three.

Example:

```
static const u32 ATTACK_EXEC = ATTACK_EXEC_OUTSIDE_KERNEL;
```

### module_dgst_pos0() - module_dgst_pos3() ###

Before we can understand exactly why this is here, we must briefly note the following:

Cracking passwords is about time. That means depending on the speed of your kernel, iteration count, etc. you will never be able to try out a certain amount of password candidates. For instance, take NTLM. This hash mode is calculated on a high-end GPU like a 2080Ti with approx. 100GH/s. If we assume that you have 8 of these GPUs in a node and if we assume that you have 1,000,000 nodes, then you will still need roughly 6,500 billion years to try out 2^127 password candidates. What I want to say with this: there is an upper limit of password candidates we can search through because we are always limited in time, no matter how much money we spent on hardware. Or from a different angle: It does not matter how many bits a hash actually outputs because what actually prevents guaranteed cracking is not its output bit size but only time to go through a specific keyspace. At this time of writing I assume with a multi million dollar budget you can search through a maximum of 56 bits per second. If we assume a runtime of 10 years we can cover another 30 bits. So it is safe to say we can never search through a keyspace which is larger than roughly 90 bits. Therefore it is safe to store only 128 bits of it in a lookup database in hashcat. That means even for SHA512 with 512 bits, we are actually only interested in 128 bits of it. That is great, so we only need to test for 128 bits instead of 512 bits and save some clocks.

That means that you have to "select" these 128 bits. This makes particular sense because a cryptographic algorithm can never calculate all of its bits at the same time in its implementation. For instance, in MD5 (128 bit) the first 32 bits are calculated first, but then followed by the last 32 bits, then the penultimate 32 bits, etc. Exactly this effect which must exist in all hash algorithms is exploited by the hashcat optimizers. After the first 32 bits are known they are checked against the database if they do not exist, no further steps of the crypto algorithm need to be calculated. This order is given in an index of 32 bit integers. That means for MD5 the first check index is 0 and the second index is not 1 but 3, etc.

To find the right values for you, just take a deep look into your crypto algorithm and figure out which parts (in 32 bit blocks) of the output hash is finished first, which one finishes next, and so on.

Example:

```
static const u32 DGST_POS0 = 0;
static const u32 DGST_POS1 = 3;
static const u32 DGST_POS2 = 2;
static const u32 DGST_POS3 = 1;
```

For slow hashes, you will normally set the "order" to 0, 1, 2 and 3, because such optimizations are of little importance here.

### module_dgst_size() ###

As you can see in the previous section, only 128 bits of the target hash are tested, but the hash must be saved entirely so that it can later be converted from its binary form back to its original form. Only you can know the size of the hash you are storing, but hashcat needs this information so that it can allocate necessary memory buffers.

Important: Hashcat will provide this buffer of the size you specified in a void buffer which you will use as *digest_buf in the decoder/encoder.

Some macros already exist because they have already been used in many modules before. A list of the well known digest sizes already defined can be found in `include/types.h`.

Example:

```
static const u32 DGST_SIZE = DGST_SIZE_4_4;
```

This scheme is a bit cryptic. It goes back to the following logic: We store 32 bit values (each 4 byte) and we have 4 of them, in that order. So the macro results in 16 bytes (128 bits).

Tip: If you have a real hash as a target, this is relatively self-explanatory. But if you are not using a real target hash, but for example some encrypted data, then it makes more sense to save this data in an "esalt" struct. From there only save the encrypted data (for example the first 16 bytes) as a digest replacement. Encrypted text has a sufficiently high entropy to provide the uniqueness that hashcat expects in the digest buffer. An "esalt" is described at the end of this document because there is two different types of salt structures used in hashcat code.

### module_hash_category() ###

This configuration has no influence on the process in hashcat, but only serves for documentation. The only time that hashcat is currently using this information is when it is called with --help. Here the modes are first sorted by category. A list of the categories already defined can be found in `include/types.h`.

Example:

```
static const u32 HASH_CATEGORY = HASH_CATEGORY_RAW_HASH;
```

If you want to add a category/type, that is not a problem. But since a change like this would change hashcat's core source, you should use a separate pull request (PR) in GIT.

### module_hash_name() ###

This configuration has no influence on the process in hashcat, but only serves for documentation. It is a simple string that you can name as you like. It is then displayed in the status view or in the --help menu.

Tip: Try to limit the length to a maximum of 48 characters, otherwise it may exceed the maximum column size in the --help menu.

Example:

```
static const char *HASH_NAME = "MD5";
```

### module_kern_type() ###

Here you specify the kernel hash mode number that this module should load. A kernel is always located under `OpenCL/mXXXXX_a[0|1|3]-[optimized|pure].cl`. This configuration is possible because of the feature to use a kernel from different modules. A good example of this is PBKDF2-HMAC-SHA512 which is used for both GRUB2 and macOS 10.8.

In theory, one could imagine implementing all such hash modes in a huge single kernel in this way, but such a kernel would become very inefficient due to the number of branches. Again, this is a trade off from readability/maintainability vs. performance. Since a password cracker is a product in which high performance is one of the most important properties, it usually ends up in a dedicated kernel for each hash mode. A look at the `OpenCL/` folder will confirm that.

Example:

```
static const u64 KERN_TYPE = 7100;
```

### module_opti_type() ###

This configuration item is a bitmask field. There are a few switches which you can enable and disable. But be careful, some of them have the potential to break your plugin. I recommend being very cautious using these flags. As always, the list of flags can be found here: `include/types.h`. I will comment the ones which exist right now:

* OPTI_TYPE_OPTIMIZED_KERNEL: This flag indicates if an optimized kernel should be used (otherwise a pure kernel will be used). It can be set by the hashcat user by passing the -O option on the command line or by hashcat if it detects that no pure kernel for that particular hash-mode exists in the `OpenCL/` folder. Note that it can also be automatically deactivated by hashcat if the user set the -O option on the command line but no optimized kernel was found. Do not set this flag from within your module.
* OPTI_TYPE_ZERO_BYTE: This indicates that the zero byte auto-optimizer is active. I have described the zero byte optimizations here: https://hashcat.net/events/p13/js-ocohaaaa.pdf. Note that with today's OpenCL/CUDA JiT many optimizations that had to be optimized by hand are done by these compilers automatically. Therefore this flag acts as a documentation flag only (it is shown as an optimizer on hashcat startup). Some other optimizers are actually used by the kernel. The downside of this is that you cannot disable these kinds of Jit compiler optimizations selectively. You can only disable them all by using the `-cl-opt-disable` flag in the JiT compiler options. there is a special function module_jit_build_options() which you can use if you want to pass it to the JiT compiler.
* OPTI_TYPE_PRECOMPUTE_INIT: similar to OPTI_TYPE_ZERO_BYTE.
* OPTI_TYPE_MEET_IN_MIDDLE: similar to OPTI_TYPE_ZERO_BYTE.
* OPTI_TYPE_EARLY_SKIP: similar to OPTI_TYPE_ZERO_BYTE.
* OPTI_TYPE_NOT_SALTED: similar to OPTI_TYPE_ZERO_BYTE.
* OPTI_TYPE_NOT_ITERATED: similar to OPTI_TYPE_ZERO_BYTE.
* OPTI_TYPE_PREPENDED_SALT: similar to OPTI_TYPE_ZERO_BYTE.
* OPTI_TYPE_APPENDED_SALT: Appended salts can be optimized as if they do not exist in some circumstances. Typically this flag makes sense for generic raw hash primitives. For instance, sha1($p.$s). This flag copies the salt data to the end of a mask in an -a 3 attack automatically. From the perspective of the mask processor (password candidate generator) the salt is a static part given by the user as part of the password. By doing so, we can save the append branch of the salt in the inner loop of the kernel which improves the performance. If the hash cracks, hashcat will automatically remove it from the mask.
* OPTI_TYPE_SINGLE_HASH: For fast hashes this will select the sXX kernels instead of the mXX kernels. The sXX kernels do not need to go through a bloom filter and no binary tree search is performed. Instead, they will store the target hash (which is just a single one) on the register level. As a result, the comparison will be much faster, and the speed improves. This flag is set by hashcat automatically on startup. Do not set this flag from within your module.
* OPTI_TYPE_SINGLE_SALT: similar to OPTI_TYPE_ZERO_BYTE.
* OPTI_TYPE_BRUTE_FORCE: This flag is a requirement for some other flags, such as OPTI_TYPE_APPENDED_SALT. Only when this flag is active, can OPTI_TYPE_APPENDED_SALT be exploited. This flag is set by hashcat automatically on startup. Do not set this flag from within your module.
* OPTI_TYPE_RAW_HASH: This flag is a requirement for some other flags, such as OPTI_TYPE_APPENDED_SALT. If this flag is active, then OPTI_TYPE_APPENDED_SALT can be exploited. This flag needs to be set from within the module, based on whether the kernel can make use of OPTI_TYPE_APPENDED_SALT.
* OPTI_TYPE_SLOW_HASH_SIMD_INIT: This flag tells the hashcat host binary to divide the number of work items with the size of the vector being used. The *_init kernel needs to be written using vector data types. Vector data types have a strong impact on CPU performance, since they will be translated from the OpenCL JiT into SSE2/AVX/AVX2/XOP instructions. Modern GPUs use scalar data types thus there is no benefit from using vector data types. This is not recommended for *_init kernels because it makes the kernel much more complicated while at the same time the _init kernel is called only once per password guess.
* OPTI_TYPE_SLOW_HASH_SIMD_LOOP: see OPTI_TYPE_SLOW_HASH_SIMD_INIT but for *_loop kernels. If it is possible for your *_loop kernel to be written in vector data types, this is highly recommended. You will typically find this option being used if the _loop kernel does not do any data-dependent branching.
* OPTI_TYPE_SLOW_HASH_SIMD_COMP: see OPTI_TYPE_SLOW_HASH_SIMD_INIT but for *_comp kernels.
* OPTI_TYPE_SLOW_HASH_SIMD_INIT2: see OPTI_TYPE_SLOW_HASH_SIMD_INIT but for *_init2 kernels.
* OPTI_TYPE_SLOW_HASH_SIMD_LOOP2: see OPTI_TYPE_SLOW_HASH_SIMD_LOOP but for *_loop2 kernels.
* OPTI_TYPE_USES_BITS_8: This flag is passed to the JiT and helps optimize some of the GPU library functions at compile time. The configuration defines the bitsize of the underlying crypto primitive.
* OPTI_TYPE_USES_BITS_16: see OPTI_TYPE_USES_BITS_8
* OPTI_TYPE_USES_BITS_32: see OPTI_TYPE_USES_BITS_8. This is the default in case no OPTI_TYPE_USES_BITS_* flag is being used. Almost all traditional crypto primitives use 32 bits: MD4, MD5, SHA1, SHA256, RipeMD160, etc.
* OPTI_TYPE_USES_BITS_64: see OPTI_TYPE_USES_BITS_8. It is important to set this flag in case your crypto primitive uses 64 bit integers. Examples: SHA512, Blake2, SHA3, Streebog, etc.
* OPTI_TYPE_REGISTER_LIMIT: This flag limits the maximum register counter to 128. This flag only has an effect on NVIDIA devices since the NVIDIA compiler is the only one that supports it. Only a few algorithms really benefit from it. It is worth testing to see if there is a performance increase, otherwise, do not use it.

### module_hash_decode() ###

The decoder function is the function that is called again and again for every line in your hashfile. We also call this sometimes the hash parser. Here you have to program the logic which decodes the line into its components and then stores them in the standardized data structure which hashcat understands.

Typically hash files are text files in which each hash is stored in a single line. Before the decoder function is called, Hashcat opens the hash file and scans the number of lines. Based on this information, it pre-allocates memory buffers for the hash digest, the salt and the esalt so you do not need to allocate any buffers from inside the decoder. If you allocate buffers from inside the decoder, you must free them as well. The size of the digest is based on what is returned from module_dgst_size(). The salt_t is a fixed size structure and the esalt size is known from module_esalt_size(). There is also some more rarely used buffers like module_hook_salt_size() but the logic is always the same. Hashcat simply multiplies the size of all these different structures by the number of lines. It then rewinds the file handle and starts iterating. For each iteration of these input lines, the module_hash_decode() function is called. The input pointer points to the new hash line and the output pointers point to the corresponding previously allocated buffers. You can directly access the pointers to store the digest, salt, esalt and other buffers without any offsets.

In hashcat there are two different types of salt structures. It is essential to understand them; please read the section "About salts" at the end of this document first. If you are unaware about the different concepts of salt_t and esalt, you really need to read that section before you continue this section.

For instance, if your crypto algorithm is something like MD5(MD5($pass.$salt)), then you can expect to find both a hash and a salt in each of your hash lines. In the decoder function, it is up to you to split these two parts (typically by using the tokenizer - please read the tokenizer section below) and copy them into a standardized hashcat structure.

You are also responsible for checking the boundaries of all the input data. The tokenizer helps you with some very specific validation routines beforehand, but some very specific tests can be done only by you. If there is an error, you can simply return from this function by setting a specific error code, such as PARSER_HASH_VALUE or some other descriptive output. As always, a list of available error codes can be found in the `include/types.h` header. If everything works okay, you need to return this function with PARSER_OK.

If you are working with salts, you need to guarantee you have set the salt_buf[] array and salt_len value. If you are writing a slow kernel, you need to guarantee you have set the salt_iter value. Please read the "About salts" section if you do not know what these variables are.

In addition to the input line and the output buffers, there are some extra buffers available for you in the decoder functions. For instance, the *hashconfig structure. Sometimes you need to execute different branches of code in the decoder, based on the user options being set. For instance, if the user sets the -O option on the command line, you can detect this from inside the decoder by checking the OPTI_TYPE_OPTIMIZED_KERNEL in hashconfig->opti_type. A good example for this is `src/modules/module_00000.c` which exploits the fact that you can reverse the Merkle-Damgard construction in optimized kernels since it is guaranteed that the password is never longer than 55 characters.

A typical decoder function covers the following actions (not all of them always apply):

* If esalt: cast esalt to plugin specific data types
* Cast void* digest array to either u32* or u64* array, based on what your algorithm uses. This is the digest buffer which is also copied to the compute devices. We will write to this buffer at the end of the function.
* Initialize tokenizer
* Configure the number of tokens based on the format of your hash lines
* Configure each token based on the format of your hash lines
* Run the tokenizer, check its result and return in case of an error
* Cast the tokenizer pointer to an element specific pointer
* Do additional boundary/limits checks on the specific pointers you just created and return in case of an error
* Convert the element specific pointers and typically write them to some local variables
* If slow hash: Set the iteration count
* Copy data (IV, salts, digests) to hashcat buffers
* Adapt buffers/variables (typically byte swaps for endianness or precomputations) based on user options
* Return with PARSER_OK

### module_hash_encode() ###

The opposite is the case with the encoder function. It is only called up as soon as hashcat has to provide the user with the hash in its original hash form. For instance, if a hash is cracked or in the status display (with single hashes). Typically you will find a number of snprintf() statements here, but for more details, there is an extra section below.

Important: Keep in mind the input buffer you get access to in the encoders are probably reused again in a later point of time. If you need to modify values before printing it to the user, make sure to not write into the original buffers. Instead, create a local buffer, copy the data to that buffer, and modify it in there.

The final hash should go to line_buf[] array and the length of the data in this array is the return value of the function itself.

Note: the general rule is that the kernel code should not do any unnecessary repetition of data manipulation (e.g byte swaps etc) because it should run as fast as possible. Instead, the encoder and decoder are host functions that are normally only executed very rarely - and therefore it is not a problem if they need to change the data a little bit to pre-compute, or adapt the data to make it look nice in the output.

### module_hash_decode_postprocess() ###

This module can be used when you have certain configuration items of a hash that you want to override with a command line parameter. A good example is the --hccapx-message-pair, where the user can add additional filter criteria so that Hashcat doesn't load a specific set of hashes from the hash list.

### module_opts_type() ###

This configuration item is a bitmask field and is very similar to the module_opti_type() function. The main difference is that here you configure general options of the workflow and not optimization specific settings. As always, the list of flags can be found here: `include/types.h`. The following list contains the flags currently supported:

* OPTS_TYPE_PT_UTF16LE: This option will generate a password based on a given mask but in UTF16LE encoding instead of raw 8 bit encoding. There are two important things to mention. First, the encoding is not a true UTF16 encoding. There is no iconv conversion done. It is a naive implementation which works by just putting zero bytes in between the characters. This is a performance-relevant optimization. This works fine for any characters that would not need utf8 to be displayed/used correctly (in other words, everything that is covered with the hashcat ?a character set). Second, it is effective only for fast hash kernels and only in -a 3 attacks. For all other attack mode kernels for fast hashes, you need to use the *_utf16le() specific functions for pure kernels or the make_utf16le() function for optimized kernels from inside the kernel manually. For slow hashes you need to use the *_utf16le() specific functions manually, too.
* OPTS_TYPE_PT_UTF16BE: Same as OPTS_TYPE_PT_UTF16LE but using big endian byte order.
* OPTS_TYPE_PT_UPPER: This needs to be used in case your hash is designed to uppercase (not capitalize!) the password before it hashes it. A good example is the LM hash. When the flag is used, this option is always active no matter which attack mode or fast vs slow hash. Note that a user can override this by using a rule which lowercases the password.
* OPTS_TYPE_PT_LOWER: Same as OPTS_TYPE_PT_UPPER but lowercase the password.
* OPTS_TYPE_PT_ADD01: This will append a 0x01 to the password. Some algorithms use stop bits like this to mark the end of the data input stream. The idea is to workaround unwanted collisions so we need to do so, too. This is effective only for fast hash kernels and only in -a 3 attacks. For all other attack mode kernels for fast hashes you need to add the 0x01 byte yourself from inside the kernel manually, typically with functions like append_0x01_4x4_S() or similar. For slow hashes, if you use the crypto libraries, they typically handle this for you.
* OPTS_TYPE_PT_ADD02: Same as OPTS_TYPE_PT_ADD01 but use 0x02 byte instead.
* OPTS_TYPE_PT_ADD80: Same as OPTS_TYPE_PT_ADD01 but use 0x80 byte instead.
* OPTS_TYPE_PT_ADDBITS14: Same as OPTS_TYPE_PT_ADD01 but add the length of the password * 8 to the 14th' 32 bit integer (Typically algorithms using little endian: MD4, MD5, RipeMD160, etc).
* OPTS_TYPE_PT_ADDBITS15: Same OPTS_TYPE_PT_ADD01 but add the length of the password * 8 to the 15th' 32 bit integer (Typically algorithms using big endian: SHA1, SHA256, etc).
* OPTS_TYPE_PT_GENERATE_LE: Generate passwords from mask in little endian byte order. This is the default if no OPTS_TYPE_PT_GENERATE_* option is set.
* OPTS_TYPE_PT_GENERATE_BE: Generate passwords from mask in big endian byte order.
* OPTS_TYPE_PT_NEVERCRACK: This option tells hashcat to continue cracking the same hashes after they have been cracked - typically, for algorithms that are known to produce a lot of false positives or to collide easily. If the user uses the --keep-guessing command line option, this option is automatically added to the opts_type variable. Do not set this option from the module.
* OPTS_TYPE_PT_ALWAYS_ASCII: This option prevents hashcat to automatically convert a password into the $HEX[...] encoding type. This automatic conversion is typically performed if the password itself contains the same character as the hash line separator character.
* OPTS_TYPE_PT_ALWAYS_HEXIFY: This option forces all the cracked passwords to be written always in hex. In this case neither "$HEX[", nor "]", is added.
* OPTS_TYPE_PT_LM: Special handling for LM passwords: all lower, 7 max, ...
* OPTS_TYPE_PT_HEX: Assume that all input data like wordlist and masks are always given in hex
* OPTS_TYPE_ST_UTF16LE: Same as OPTS_TYPE_PT_UTF16LE but applied on the salt buffer.
* OPTS_TYPE_ST_UTF16BE: Same as OPTS_TYPE_PT_UTF16BE but applied on the salt buffer.
* OPTS_TYPE_ST_UPPER: Same as OPTS_TYPE_PT_UPPER but applied on the salt buffer.
* OPTS_TYPE_ST_LOWER: Same as OPTS_TYPE_PT_LOWER but applied on the salt buffer.
* OPTS_TYPE_ST_ADD01: Same as OPTS_TYPE_PT_ADD01 but applied on the salt buffer.
* OPTS_TYPE_ST_ADD02: Same as OPTS_TYPE_PT_ADD02 but applied on the salt buffer.
* OPTS_TYPE_ST_ADD80: Same as OPTS_TYPE_PT_ADD80 but applied on the salt buffer.
* OPTS_TYPE_ST_ADDBITS14: Same as OPTS_TYPE_PT_ADDBITS14 but applied on the salt buffer.
* OPTS_TYPE_ST_ADDBITS15: Same as OPTS_TYPE_PT_ADDBITS15 but applied on the salt buffer.
* OPTS_TYPE_ST_HEX: Same as OPTS_TYPE_PT_HEX but applied on the salt buffer.
* OPTS_TYPE_ST_BASE64: Same as OPTS_TYPE_ST_HEX but using base64 encoding.
* OPTS_TYPE_HASH_COPY: This copies the original input hash line as it is into a buffer so that it can be used later. This is required if the original input hash line ships with the same data which is not copied into salt_t or esalt buffer because it is overhead data which is not used in any way. The hash line is copied to the buffer hash_info->orighash and can be used from the encoder function by simply returning hash_info->orighash. Please do not abuse this functionality, for two reasons: First, by being able to reconstruct the original hash line from only the hashcat data we verify that the correct amount of data has been stored in the hashcat memory structures (IOW, it is a good verification process). Second, the host memory requirement for saving this data increases drastically.
* OPTS_TYPE_HASH_SPLIT: This needs to be used if the hash actually contains multiple hashes in the same hash line. A good example is the LM hash which is typically stored as a 128 bit hash, but actually is built on two 64 bit hashes.
* OPTS_TYPE_LOOP_PREPARE: TBD
* OPTS_TYPE_LOOP_EXTENDED: This flag can be used if you want to execute a *_loop_extended kernel directly each time a _loop kernel is finished. This actually means directly after each _loop kernel invocation when no final values are ready. The _loop kernel typically only iterates for a maximum of 1024 iterations and then returns. This provides low kernel runtimes, which reduces GPU screen lags and avoids driver watchdog events. However, some algorithms can be exploited by working on exactly these intermediate values.
* OPTS_TYPE_HOOK12: Execute a hook kernel (CPU code) between _init and _loop kernel. A hook kernel is a normal kernel which can be used to select/copy very specific intermediate data and copy it to a so-called hook transfer buffer. This transfer buffer exists on both GPU and CPU. After the kernel is completed, the GPU buffer is copied to the corresponding CPU buffer so it can be processed. Then, the real hook function from your module is called from which you can read the intermediate data, process it as you need and then store it back. After your CPU function is finished, the buffer is copied back to the GPU automatically. The typical use case for this is if you need to deal with algorithms which include libraries which have no GPU implementation. Hashcat will automatically spawn a number of threads for you, so this is a multi threaded process. All buffers which are not constant buffers are thread-safe.
* OPTS_TYPE_HOOK23: Same as OPTS_TYPE_HOOK12 but the hook is between the _loop and the _comp kernel. Do not confuse this with OPTS_TYPE_LOOP_EXTENDED. A hook is always when the final values are ready to be processed. We believe most algorithms that need hook code will use this hook instead of OPTS_TYPE_HOOK12.
* OPTS_TYPE_INIT2: Some algorithms (usually updated from previous crypto schemes) execute two different types of compute intensive derivation functions. A good example is iTunes 10+. In iTunes 9 there is an algorithm with 10,000 iterations of SHA256. However, Apple updated this algorithm to be backward compatible. They use the output of the iTunes 9 KDF as the password to a new KDF which is 10,000,000 iterations of SHA256. The problem is that even for a KDF with 10,000 iteration we need to split this. In this instance we split this into 10 calls to a _loop kernel with 1,000 iteration otherwise users get massive screen lags or some watchdogs restart the drivers. In such a case, you can use OPTS_TYPE_INIT2 and OPTS_TYPE_LOOP2 kernels where you can execute the updated KDF with 10,000,000 iterations and also split it into 1,000 iteration chunks.
* OPTS_TYPE_LOOP2_PREPARE: TBD
* OPTS_TYPE_LOOP2: See OPTS_TYPE_INIT2
* OPTS_TYPE_AUX1: Some hash algorithms, often those with backward compatibility, share the same KDF (for instance, PBKDF2-HMAC-SHA1) but also use the derived key differently, depending on a version number. In theory you can check this version in the _comp kernel and build two different branches inside the _comp kernel. In many cases this is implemented like this. The AUX kernels are an alternative where you can assign the different branches to specific kernels. This greatly reduces instruction cache misses and helps the JiT to produce better code. It can also help in cases where both branches require a certain amount of shared memory that is larger then you are able to allocate. In case you use AUX kernels, the _comp kernel is executed, but it is expected to be empty.
* OPTS_TYPE_AUX2: See OPTS_TYPE_AUX1, but for a different branch.
* OPTS_TYPE_AUX3: See OPTS_TYPE_AUX1, but for a different branch.
* OPTS_TYPE_AUX4: See OPTS_TYPE_AUX1, but for a different branch.
* OPTS_TYPE_BINARY_HASHFILE: Use this in case your hash file contains binary data. As you can imagine, a bit of special handling is required. For normal hash files with only text data, hashcat reads the file line by line and for each line the decoder function is called. For binary data you can decide yourself if you want to use hashcat to load the binary data and present it in the line_buf[] buffer or if you want to iterate through the binary data yourself. If you select the first variant (default) this has the disadvantage that you can only load a single hash. If you want to load multiple hashes from binary data, then you need to understand that it is unknown to hashcat how to iterate through different "hashes" because it cannot know the binary structure. However, hashcat needs to know the number of hashes that are included in the binary file in order to allocate the required memory structure. In the first step, hashcat calls the module function module_hash_binary_count() in which you need to return the number of hashes which will be read from this particular binary data. In a second step, the module function module_hash_binary_parse() is called in which you have to implement the logic to iterate through the different hashes yourself. In theory there is no need to provide module_hash_decode() because it is not called by hashcat, however in the spirit of good programming we recommend to stick to this function for binary hashes as well. Use the module_hash_binary_parse() to load the binary data and prepare the chunks and then call module_hash_decode() and provide the hash. Then regularly parse the data in module_hash_decode() and copy its data to hashcat structures. For easy single hash loading of binary data you can take a look at `src/modules/module_05200.c` and for a multi hash example take a look at `src/modules/module_02500.c`. Note that for the WPA example there is also a lot of other functions involved to deal with binary data, such as writing the binary data in case a hash was cracked.
* OPTS_TYPE_BINARY_HASHFILE_OPTIONAL: This option can be used in combination with OPTS_TYPE_BINARY_HASHFILE but is there for backward compatibility. See -m 22000 as an example. This mode can have hashfiles either in binary or in plaintext. In this situation you need the binary decoder in order to decode the binary data and then re encode it  so that you can load it in the plaintext decoder. This also enables you to have hashes on the command line, even if the mode has the OPTS_TYPE_BINARY_HASHFILE option set.
* OPTS_TYPE_PT_ADD02: Same as OPTS_TYPE_PT_ADD01 but use 0x02 byte instead.
* OPTS_TYPE_KEYBOARD_MAPPING: there are a few algorithms which support the remapping of characters from inside the kernel. The configuration of the mapping can be loaded from the hashcat host binary on startup, thus it is required to set this option to let the hashcat host binary know that your kernel will support this functionality. Please read `docs/keyboard-layout-mapping.md` for a detailed explanation.
* OPTS_TYPE_DEEP_COMP_KERNEL: This option is used for algorithms that use a salt which is related but unlinked from the esalt. Use this in case you want the hashcat host binary to iterate through the different esalts in the _comp kernel for you. This is a very complex scenario which requires a detailed explanation. Please refer to the section "Data Structures: salt_t vs esalt" at the end of this documentation. A good example is `src/modules/module_22000.c`.
* OPTS_TYPE_TM_KERNEL: This option works for fast hashes only. It enables you to run a special transpose multiplier (TM) kernel prior to each kernel invocation. This can be handy for bitsliced kernels where you have to transpose the multiplier data, for instance in a 32x32 matrix. Typically doing this kind of operation forces you to use fixed kernel loop count, so that you have guaranteed fixed size data blocks to transpose. You can do so by using the same fixed value from module_kernel_loops_min() and module_kernel_loops_max(). However, a transpose matrix is just application. Feel free to exploit this kernel for your own needs.
* OPTS_TYPE_SUGGEST_KG: This option prints a warning screen to the user on startup of hashcat. You can use this option to inform the user that your plugin is known to emit collisions and/or false positives and to suggest use of the --keep-guessing option. We do not want to enable this option by default - otherwise, the user would have no chance to disable it since there is no --no-keep-guessing option.
* OPTS_TYPE_COPY_TMPS: This option tells the hashcat host binary to copy the `tmps` data structure from the compute device to the host in case a hash was cracked. In order to access this data, you need to implement and register the module function module_build_plain_postprocess(). There are several scenarios in which this can be useful. For instance, if you have a weak algorithm that could be exploited to leak portions of the password and you use this leaked data to speed up your attacks, you still need to know the leaked data on the host to copy it to the password buffer before printing it to the user. A good example for this is PKZIP `src/modules/module_20510.c` which leaks the first 6 bytes of the password. Another scenario is the PIM brute force in VeraCrypt. The PIM in this case can be seen as an additional numeric password. In case we crack it, the user needs to know both the password and the PIM in order to mount the volume.
* OPTS_TYPE_POTFILE_NOPASS: This option simply prevents the hashcat host binary from adding a cracked hash to the potfile. For instance, if a specific hashing algorithm is implemented with several hash formats and therefore your plugins hash format shares the same format with a different plugin hash format (think of it like a format clash where the potfile parser could not really decide if it is the correct hash format to accept). A good example is the WPA PMK, which cannot be used to login to a specific WPA network directly. There could be other reasons for not printing the cracked hashes to the potfile.
* OPTS_TYPE_DYNAMIC_SHARED: This is a very special option which tells the hashcat host binary to query the real available shared memory on a device for a particular kernel. In addition it will also register the queried amount of shared memory from the host. On NVIDIA, this allows us to use the full available shared memory (regions in the post 48k range), though we still need to prepare the kernel in order to make use of the dynamic allocated shared memory. A good example is the bcrypt kernel `OpenCL/m03200-pure.cl`.
* OPTS_TYPE_SELF_TEST_DISABLE: This option can be used if you want to disable the self-test functionality for your hash-mode. Valid reasons to disable this feature are: Your OpenCL kernel is using compile time optimizations such as fixed salts (like in DESCrypt), the hash primitive to be used has to be derived first from the target hash (like in JWT) or the hash-mode is so slow that it hurts startup time of hashcat (like in Ethereum Wallet SCRYPT). For the first two cases the problem is that hashcat would create a cached optimized OpenCL kernel with a configuration which is valid only for the self-test hash, but very likely the wrong ones for the real target hash. The real target hash would never crack.
* OPTS_TYPE_MP_MULTI_DISABLE: Do not multiply the kernel-accel with the multiprocessor count per device to allow more fine-tuned workload settings.
* OPTS_TYPE_NATIVE_THREADS: Forces "native" thread count: CPU=1, GPU-Intel=8, GPU-AMD=64 (wavefront), GPU-NV=32 (warps). Does not override user-defined -u value.
* OPTS_TYPE_POST_AMP_UTF16LE: Run the true UTF8 to UTF16LE conversion kernel after they have been processed from amplifiers. Works only for slow-hash kernels.
* OPTS_TYPE_AUTODETECT_DISABLE: Skip this hash-mode from being used by the autodetect engine

### module_salt_type() ###

This option tells hashcat that your hash is salted. Not all hashes are salted (mainly raw hashes have no salt). If they are salted, hashcat needs to know which strategy to use for storing the hashes. Here are the possible options:

* SALT_TYPE_NONE: This type is used if the hash is not salted.
* SALT_TYPE_EMBEDDED: This type is used if you have a strict hash format ruleset and you do not need to give the user the opportunity to use --hex-salt. You should use this type if there are dedicated extraction tools for your hash or if you are under the control of the extraction tool (so that you can make changes to it).
* SALT_TYPE_GENERIC: This type is used if you have a generic salt, that is if the salt is part of a hash line which does not go back to a strict formatting ruleset. Typically if you need to implement a hash mode for which you know there are multiple exporting tools that work slightly differently. This mode is required if you want to enable the use of --hex-salt for the user.
* SALT_TYPE_VIRTUAL: This type is used if you want to reuse an existing kernel implementation of a hash mode which normally expects a salt, but for this variant you want to support loading a hash file in a format that does not ship with a salt. You will generate a `virtual` salt that is always the same (typically empty) and set the data in the decoder function accordingly. A good example for this is md5(md5($p)) which shares the same kernel with vBull (which is md5(md5($p).$s).

### module_st_hash() ###

Here you provide a hash for the self-test functionality. You also need to provide the correct password for this hash later. Please only use artificial hashes which you generated yourself. Typically this is a hash with the password "hashcat" which you have generated by using test.pl in passthrough mode.

Note that this hash will also be used as reference for the benchmark mode. In some rare circumstances to have a not too long running iteration count to reduce startup time delays. A good example for this is iTunes 10+ `src/modules/module_14800.c`. This can also be done using test.pl.

The --example-hashes command line argument together with a specific hash mode (-m) will also instruct hashcat to show the example hash and example password.

### module_st_pass() ###

This is the password to crack the hash given in module_st_hash() for the self-test functionality.

### module_hook_extra_param_init() and module_hook_extra_param_term() ###

These two functions were added to hashcat beginning with version 6.2.0 when it was required for a module to use a 3rd party library from inside a hook function. However, the module developer is free to decide how to use this buffer (it doesn't have to be a library handle). Generally, it is a buffer that the module developer would use for something that they need to initialize and terminate only once on startup and shutdown for performance reasons.

It is unclear to hashcat if this buffer will be handled in a thread-safe fashion or not, but since hooks are multi-threaded, hashcat will allocate multiple buffers (as many as there are hook threads) of this type for the module developer. This enables the module developer to load 3rd party libraries where they have no control over and which are known to not be thread-safe.

The module developer does not have to care about managing the multiple instances but has to provide the size of the buffer to be allocated. For this, they have to use the module_hook_extra_param_size() function. The buffer in *hook_extra_param is zeroed and ready to be written when module_hook_extra_param_init() is called. On startup, hashcat will call module_hook_extra_param_init() that many times as there are hook threads each time providing the module function with a new buffer. The same logic applies to module_hook_extra_param_term() on shutdown. Hashcat will also free the memory on shutdown.

A good example for this is: `src/modules/module_11600.c` and `src/modules/module_23800.c`

### module_benchmark_mask() ###

This is a mask that is hash mode specific and is normally used whenever the mask that should be used in benchmarks is of a very specific length and/or pattern. This could be a dynamic string, but in general try to use a variable called `BENCHMARK_MASK`.

### module_benchmark_charset() ###

This is a custom charset setting (like `--custom-charset1`) that always needs to be synchronized with the default benchmark mask (see `module_benchmark_mask ()`, or the default one if not set). This setting does only affect `--benchmark` and you can use this charset within your mask with `?1`. Try to use a variable called `BENCHMARK_CHARSET` for this string whenever possible.

### module_benchmark_salt() ###

This is a salt that is hash mode specific and allows you to set a `salt_t` structure dynamically. This could sometimes be needed if custom iteration counts or salt lengths are needed for a specific hash mode.

## Kernel ##

This is the second necessary ingredient for creating a plugin. Particular attention should be paid to the development of the kernel. Compiling the kernel takes a relatively long time, so both hashcat and the various compute APIs try to save a binary kernel in a cached structure. This serves to reduce the startup time and it is important for the user experience (UX). This however can be a pain as a developer.

NOTE: You -must- manually delete all cached kernels with every change to your kernel code. This is -very- important!

```
$ rm -rf kernels/
```

Note: `make clean` will automatically remove all cached kernels, but the recompilation with `make` of the whole hashcat binary will of course take much longer and this is therefore not recommended.

Keep in mind that a GPU is a multi-core device; hashcat will always try to utilize the parallelization power of the hardware as much as possible. This can be undesirable behavior while you are developing a kernel. Especially when you start using printf() - your console can get flooded easily with debugging information because hundreds of work items will be executed. Keep in mind that the printf() will be called for every workitem.

Additionally, there are a couple of kernel invocations which are unwanted when developing a kernel. They go back to the self-test functionality and the autotune engine. Both features are important for user experience. Keep in mind that the input password for these kernels invocation are not based on the password candidate you expect. It is therefore recommended to disable these features while developing the kernel.

To enable some of the special developing functionalities - for example, to disable the autotune - you need to unlock these undocumented features first. The first step is to enable debugging in `src/Makefile` by setting DEBUG to `1`. Run a `make clean` afterwards.

Typically you want to develop the kernel with the least amount of unwanted side effects and we should invest in some proper preparation before actually starting writing code. A good example for this is the hash which you are using. Hashcat supports the hash given at the command line, but the command line can create unwanted side effects. For instance, the `$` character could be part of the hash and you forgot to quote it correctly. The safer way is to write the hash and the password into separate files, as this will generally avoid any problems with interpretation from the shell. Of course this is not required, but it is the mindset which I am trying to emphasize.

Additionally there is a couple of command line parameters that you want to use:

* --potfile-disable: The moment when your implementation is almost complete and you start cracking the hash for the first time as expected it is very likely it will turn out some other things are not perfect. For instance, the encoding of the cracked hash. So you need to change some code and run hashcat again to verify this option will prevent hashcat from writing the cracked hash to the potfile. This will allow you to restart hashcat without the need to remove the potfile manually.
* --self-test-disable: The self-test feature serves to test the kernel each time the user starts hashcat to ensure it works on the users hardware as expected. Hashcat does not know you are implementing a new kernel, so it will call the kernel you are implementing, too. This has two unwanted side-effects. First, it will print a self-test failure which is clear to us, but not to hashcat. Second and more relevant, if you use printf(), it is very likely to print values which you are not expecting. This is because you are expecting values based on the hash or password you gave on the command line, not the values produced by the self-test hash or self-test password. If you use the same hash and password, you may wonder why it is printed twice.
* -n 1 -u 1 -T 1: The combination of these three options with these exact values will disable the auto tune. This is hardcoded into hashcat. This is an undocumented feature. The auto tune will create the same problems as the self-test feature. You need to use --force to be able to use these manual tuning parameters.
* --quiet: When you are expecting printf() results, try to limit the hashcat output to a minimum. The printf() itself is not affected by this option.
* --backend-vector-width 1: Only required if you are developing the kernel by using a CPU as compute device. Printing elements from vector data types is possible (for instance `printf (a.s1);`), but we should avoid any influence. Some OpenCL runtimes even support printf() of a vector data type, which results in very weird outputs.
* -d 1: In case you have multi compute devices in your system, limit it to a single compute device. This is to reduce startup and JiT compile time.

Typically a developer command line for hashcat looks the following:

```
$ rm -rf kernels $HOME/.nv; ./hashcat -m XXXXX hash.txt word.txt --potfile-disable --self-test-disable -n 1 -u 1 -T 1 --quiet --backend-vector-width 1 -d 1 --force
```

When adding print statements keep in mind that you need to manually add a conditional to branch on a specific loop position, otherwise every parallel execution of the kernel will execute the printf(), flooding your terminal. So you can use either:

```
if ((loop_pos + i) == 0) printf ("%08x\n", a);
```

from a _loop kernel, or

```
if ((gid == 0) && (lid == 0)) printf ("%08x\n", a);
```

from a kernel without _loop.

Some last recommendations about printf() itself. Printing a string %s is not recommended. Missing zero bytes or big endian byte order can be very confusing. Instead try to use only the %08x template for everything. Especially for strings this makes a lot of sense, if for example you want to find unexpected non zero bytes. This can be done by calling printf() multiple times. Get used to this and it will simplify a lot of things for you.

To decide which type of kernel you want to write (pure or optimized), here are some recommendations when to write an optimized kernel implementation:

* If your algorithm can be optimized by artificially limiting the password or salt length to a specific range it makes sense to have an optimized kernel implementation. But note, this does not exclude the need for a pure kernel implementation for longer passwords.
* If your algorithm is limited to a maximum length per password, for example 8 characters, the previous recommendation applies the same way. But in this case it does not even make any sense to have a pure kernel implementation because the optimized kernels hashcat support passwords up to length 31.
* If your algorithm has some known weaknesses you probably cannot use the hashcat crypto library because to have full control you have to re-implement the hash in your own function. A good example is NTLM and the meet-in-the-middle optimization. If no hashcat crypto library is being used, you probably want to implement this in an optimized kernel.
* If your algorithm can be optimized based on the chosen attack-mode, it should be covered using an optimized kernel because you probably need to re-implement the hash in your own function.

These recommendations apply for both fast and slow hashes.

In most cases, however, the code for the hash is exactly the same. In these cases you probably want to only implement a pure kernel.

### Kernel parameters ###

Hashcat will call all kernels with exactly the same parameters. In most cases only a few of the parameters are used, but on the other hand they do not have a negative impact on the performance. Having a fixed prototype for all kernels makes it easier to work with all the different buffers and generally makes it easier to read kernels from other people.

There is no need for you to change anything. This section is only for information. While it is not relevant for you to know all the different parameters, at least some of them are important to know. Never write to any of them directly unless you know about the implications. Use the macros provided if you want to write something. Most of the buffer you do not even need to read from. The ones that are interesting for reading I will mark in the description.

* pw_t *pws: In fast hash kernel mode, this is the buffer of the base passwords. In slow hash kernel mode, this is the buffer of the passwords. You want to read from this buffer. There is one entry for each work item.
* kernel_rule_t *rules_buf: This is the buffer which holds the configuration of the modifier rules. In fast hash mode you want to read this buffer from the inner loop in your _a0 kernels.
* pw_t *combs_buf: This is the buffer which holds the modifier passwords. In fast hash mode you want to read this buffer from the inner loop in your _a1 kernels.
* void *bfs_buf: This is the buffer which holds the modifier part of the password mask. In fast hash mode you want to read this buffer from the inner loop in your _a3 kernels.
* void *tmps: This is the generic context buffer. It is available only in slow hash kernel mode. In slow hash mode you want to read and write this buffer. There is one entry for each work item.
* void *hooks: This is the generic hook buffer. It is available only in slow hash kernel mode and if hooks are enabled. In slow hash mode you want to read and write this buffer. There is one entry for each work item.
* u32 *bitmaps_buf_s1_a: This is the bitmap for the bloom filter which is used in a fast-hash multi-hash kernel.
* u32 *bitmaps_buf_s1_b: See bitmaps_buf_s1_a.
* u32 *bitmaps_buf_s1_c: See bitmaps_buf_s1_a.
* u32 *bitmaps_buf_s1_d: See bitmaps_buf_s1_a.
* u32 *bitmaps_buf_s2_a: See bitmaps_buf_s1_a.
* u32 *bitmaps_buf_s2_b: See bitmaps_buf_s1_a.
* u32 *bitmaps_buf_s2_c: See bitmaps_buf_s1_a.
* u32 *bitmaps_buf_s2_d: See bitmaps_buf_s1_a.
* plain_t *plains_buf: This is where hashcat stores the index to the base password and the modifier (if used) of a cracked hash. This buffer is used by hashcat to reproduce the password on the host and print it to the user along with the hash. The buffer has as many entries as there are unique digests.
* digest_t *digests_buf: This is the one big buffer which holds all unique digests. It is searched using a binary search after the hash passed the bloom filter.
* u32 *hashes_shown: This is a buffer which marks individual hashes as cracked after they have been cracked. This way we do not report the same hash cracked twice or more often.
* salt_t *salt_bufs: This is the buffer which holds the fixed size salt data. See the salt_t section below for details. If you are using a fixed size salt data, read from here. There are as many entries as there are unique salt_t buffers, but you do not need to iterate through them from inside the kernel. Use the "salt_pos" variable (see below) to index the current one.
* void *esalt_bufs: This is the buffer which holds the generic size salt data. You need to cast this type from inside the kernel manually. There are as many entries as there are unique digests, but you do not need to iterate through them from inside the kernel. Use the "digests_offset" variable (see below) to index the current one.
* u32 *d_return_buf: This buffer is used to indicate to hashcat that a hash has been cracked and should be shown to the user.
* void *d_extra0_buf: This buffer is used to workaround the OpenCL memory limitation that only a maximum of 1/4 of the total device memory can be used from a single allocation. Some algorithms, especially memory hard algorithms, can make use of this.
* void *d_extra1_buf: See d_extra0_buf.
* void *d_extra2_buf: See d_extra0_buf.
* void *d_extra3_buf: See d_extra0_buf.
* u32 bitmap_mask: This is the mask for the bloom filter. It depends on the bitmap size which was automatically calculated from hashcat on startup.
* u32 bitmap_shift1: This is the shift of the individual hash elements which is used for the bitmaps of type 1. There are two different data shifts to reduce the number of collisions in the bitmap.
* u32 bitmap_shift2: See bitmap_shift1.
* u32 salt_pos: This variable is used to index the current salt_t entry. You want to use this when you access the salt_bufs buffer.
* u32 loop_pos: This is the current iteration number to start with. If you have a slow hash kernel, this variable is relevant in the _loop kernel. Since the _loop kernel is limited to a maximum iteration count of 1024, some algorithms have higher iteration counts and have iteration count depending logic implemented.
* u32 loop_cnt: This is the number of iteration counts to loop in the inner loop in the _loop kernel. Typically not higher than 1024.
* u32 il_cnt: This is the number of iteration counts to loop in the inner loop in a fast hash kernel. Typically not higher than 1024. There is no offset needed because the modification buffers are maintained by hashcat and never exceed 512 entries. This enables hashcat to store the modifiers in the constant memory of the device.
* u32 digests_cnt: This is the total number of unique digests in the digests_buf array of the current salt. It is important for the binary search.
* u32 digests_offset: This is the offset to the first entry or unique digests in the digests_buf array of the current salt. It is important for the binary search.
* u32 combs_mode: This is a specific configuration for combinator based attack in slow hash mode. It defines which side (left or right) is the base and which is the modifier side. You want to access this variable from your _a1 kernels.
* u64 gid_max: This is the total number of unique work items started from the host program. Each work item needs to identify itself using the `get_global_id (0);` and check if the number is smaller than this variable. This goes back to the requirement of clEnqueueNDRangeKernel() that the total number of work items has to be a multiple of the thread count and therefore could be higher than the actual number of password candidates to test. If such a work item accidentally would crack the hash, the host binary would run into a out of boundary read because it could not find the corresponding base password.

The large number of kernel parameters can be confusing when writing a kernel. But since they never change, we can easily replace them with a macro. There is a couple of kernel parameter replacement macros where you need to choose one from for your kernel:

* KERN_ATTR_BASIC(): Use this in your fast hash kernel if this is attack mode 1 or 3 and not using vector data types.
* KERN_ATTR_BITSLICE(): Use this your fast hash kernel is using a bitsliced implementation. This requires the modifier buffers to be preprocessed with a TM kernel beforehand.
* KERN_ATTR_ESALT(e): Use this if your fast hash kernel uses an esalt structure.
* KERN_ATTR_RULES(): Use this in your fast hash kernel if this is attack mode 0.
* KERN_ATTR_RULES_ESALT(e): Use this in your fast hash kernel if this is attack mode 0 and uses an esalt structure.
* KERN_ATTR_TMPS(t): Use this if your slow hash kernel only uses a tmps structure.
* KERN_ATTR_TMPS_ESALT(t,e): Use this if your slow hash kernel uses a tmps structure and an esalt structure.
* KERN_ATTR_TMPS_HOOKS(t,h): Use this if your slow hash kernel uses a tmps structure and a hook structure.
* KERN_ATTR_TMPS_HOOKS_ESALT(t,h,e): Use this if your slow hash kernel uses a tmps structure, a hook structure and an esalt structure.
* KERN_ATTR_VECTOR(): Use this if your fast hash kernel uses vector data types in the inner loop. Note: Only valid for -a 3 kernels.
* KERN_ATTR_VECTOR_ESALT(e): Use this if your fast hash kernel uses vector data types in the inner loop and uses an esalt structure. Note: Only valid for -a 3 kernels.

### Kernel: fast hash type ###

The fast hash type is needed if we are cracking a hash that is so fast to compute that the PCI express bottleneck is taking more time than to compute the hash. These raw hashes are designed to compute very fast intentionally. They typically consist of only binary or arithmetic operations either with none or limited memory access. That means they often can be implemented on register level. On the other hand, if we need to access any memory structures just to provide the password candidates, it will hurt the performance significantly. Therefore the general concept of a fast hash kernel is to load a base password candidate directly onto a register and run a for() loop within the kernel which modifies the base password candidate.

The modification is depending on the attack-mode. Hashcat supports 5 different attack-modes with the -a command line flag (0, 1, 3, 6 and 7) but attack-mode 6 and attack-mode 7 share the same kernel code with attack-mode 1. This means we have to implement three kernels. These kernels are implemented in three kernel source files (0, 1, 3). Based on the attack-mode selected by the user on startup, hashcat will load the corresponding kernel.

The file name convention for fast hashes is: `OpenCL/mXXXXX_a[0|1|3]-[pure|optimized].cl`

#### Kernel: fast hash type (optimized) ####

As you can see from this convention, you actually have to implement six kernels if you want to add a full featured fast hash mode to hashcat. It is up to you if you want to save some time only implementing a pure kernel, only an optimized kernel or both. But in each case you must implement all three attack modes to support all the different attack types supported by hashcat.

Remember we only need to have those three different implementations due to the different ways the password candidate is generated. You may think it would be easier to have like three branches but these branches would already decrease the performance drastically.

Each fast hash kernel source in optimized mode has to provide the following kernel functions with this convention: `mXXXXX_[m|s][04|08|16]`.

As always, the XXXXX is the hash mode with leading zeros. The `m` or `s` defines the multi-hash and single-hash implementation. In single hashes, often we can store the target hash on the register which makes the final test much faster compared to checking it on GPU memory. The `m` and `s` therefore often look almost the same. The only difference is that in the `s` kernel at some point you will store the target hash in a register. The final comparison function macro for `m` is COMPARE_M_SIMD() and for `s` is COMPARE_S_SIMD().
For single-hash this will add code to do on-register comparison. For multi-hash this will add the code to run the bloom filter and a binary tree search. For both cases, the macros expect you to provide 4 times 32 bit values in the same order as you have configured in the module functions module_dgst_pos0() - module_dgst_pos3(). Note that it always has to be 4 times 32 bit values, also for hashes which provide much more or much less bits output size. See the sections about `module_dgst_pos0()` - `module_dgst_pos3()` for details.

The `[04|08|16]` from the function name denotes the maximum password candidate length in 4-byte words. The `04` function limits the candidates to 16 bytes, `08` limits to 32 bytes, and `16` to 64 bytes. Only the brute-force `a3` set of kernels need to implement all of the `04`, `08`, and `16` length variants. The `a0` and `a1` sets of kernels should only implement the `04` function and create the `08` and `16` variants as empty stubs. The candidate generation for the fast `a0` and `a1` kernels are proportionally slow enough that the length optimizations of the `08` and `16` variants simply don't provide significant benefit over the "pure" variant.

There are some kernels where using vector data types are beneficial even if they are executed on compute devices which have no native support for vector data types. A good example is NTLM running on a high end GPU. The performance gain comes from how the algorithm works and that there is in total 60 instructions that can be precomputed based only on the scalar base password. The base password never changes. The vectorization is done only in the inner loop, but from there it can access the precomputed (scalar) values from the outer loop. It saves both, instructions and resources. This is done automatically by the compiler because the structure of hashcat kernels allows the compiler to optimize it.

#### Kernel: fast hash type (pure) ####

The main purpose of pure kernels is to support long passwords (and salts) up to length 256. However, pure kernels are much easier to write than optimized kernels. First, it is only a single-hash and a multi-hash kernel to code. Second, it is expected you use the hashcat crypto libraries, for instance `OpenCL/inc_hash_sha256.cl`. To use the hashcat crypto libraries requires some detailed knowledge, please check the section on the hashcat crypto library below.

Each fast hash kernel source in pure mode has to provide the following kernel functions with this convention: `mXXXXX_[mxx|sxx]`.

The pure kernels are supposed to run slower than optimized kernels, but it is hard to define a percentage which shows the performance difference because it largely depends on what kind of optimization you can use. For instance, for NTLM in which you can do meet-in-the-middle tests, the optimized kernel is around three times faster than the pure kernel. On contrary, for SHA256-HMAC they have exactly the same performance.

### Kernel: slow hash type ###

Do not get the word "slow" in "slow kernel" wrong. This only means that the expected speed is so slow (or better said, the algorithm is so demanding) that the PCI Express Bottleneck is no longer relevant.

The slow hash kernel also supports pure and optimized kernel implementations.

In most cases you will develop only pure kernel implementations. An optimized slow hash implementation makes sense only if the _loop kernel uses parts of data (like the password or a salt) in its original form. Then you can do password length based optimizations. A good example is `OpenCL/m00500-optimized.cl`. However, these kernels are rare and therefore I will only describe the pure kernel implementation. There is also a specific kernel that I recommend looking at, `OpenCL/m00500-pure.cl`, you can use it for comparison.

As already mentioned, most slow hash modes do not use password length specific kernels like in a fast hash kernel. There is no "s04", "s08" kernels or anything like this. Dedicated single and multi-hash kernels also do not exist in this case, because it wouldn't make any sense or performance difference.

There are three kernels you need to implement. This means that you need to split the algorithm into a part which is done for initialization, a part which does the iterations (typically the part of the code which makes it slow) and final part where you do some comparisons or tests to see if the derived key matches. These kernels are:

* mXXXXX_init: This is the first kernel which is called. In here you load the password candidate, convert it to UTF16 or a different endianness if needed, then store some precomputed values or crypto primitive contexts derived from passwords and salts and initialize the `tmps` buffer.
* mXXXXX_loop: This is where you put the real work intensive computation. Typically KDFs become slow artificially. They use a fast crypto primitive to produce some hash output and then use this hash output as input to another "round", and so on. There are some exceptions to this like scrypt, but in most cases there are some sort of iterations involved. Put them here. Note that hashcat will never execute all iterations in one big loop. This would create a very laggy screen to the user and some driver watch dogs will kill the kernel because it will think the algorithm hangs due to the long runtime. Typically no more than 1024 iterations per kernel invocation are executed (you can override this value, but only within the module). In order to achieve this we need to read the current context state from a special buffer `tmps` (which is explained below in detail) at the beginning of the kernel, then do the iterations in a loop and finally store the context state to the `tmps` buffer. When the _loop kernel is called again, it reads the `tmps` buffer which we set in the previous _loop kernel and continues from there. This goes up to the point that salt->salt_iter is reached.
* mXXXXX_comp: This kernel is called after the _loop kernel finished with the last iteration. Basically this is when the KDF is finished deriving some sort of key. This key often is used to decrypt some data. For some more generic KDF, the key can be used like a hash and you just call the macro to look it up in the database. This typically is the part which takes the most time to develop because the code is more complex. Often you have to match some patterns or test for known plaintexts but this is fresh code which you probably won't find in any of the other kernels. The _init and _loop kernels often can simply be copied from other kernels. The simple _loop kernel typically is much slower compared to the more complicated _comp kernel. That means it is often not worth to spend too much effort into optimization of the _comp kernel.

It is obvious, but the kernels are executed in exactly this order: mXXXXX_init, mXXXXX_loop(N), mXXXXX_comp.

Along with the three kernels goes a context buffer called `tmps` which is accessible for read and write by all three kernels. The data type of this buffer is a void* and you cast it to a structure you need from inside the kernel. Hashcat knows about the size of the buffer because you returned it in the module in the module_tmp_size() method. This buffer is unique for every work item executed on the compute device. This means that hashcat will allocate a buffer on the compute device which has the size of your structure multiplied with the maximum possible work items which was discovered by the auto tuner. Each password candidate has its own `tmps` buffer allocated. The buffer is thread safe and free to be read or written to. You do not need to care about race conditions, mutexes, etc.

Typically it goes like this:

* In the "mXXXXX_init" kernel you write into `tmps` at the end.
* In the "mXXXXX_loop" kernel you read from `tmps` at the beginning and write into `tmps` at the end.
* In the "mXXXXX_comp" kernel you read from `tmps` at the beginning.

For slow hashes it is recommended to use vector data types if your algorithm allows to do so. If you use vector data types, use it in the _loop kernel only. Make sure to inform hashcat about using the appropriate opts_type option (see modules section).

## Hashcat Crypto Library ##

The hashcat crypto library interface is very close to the OpenSSL interface with the typical Init(), Update() and Final() calls. But there are some important differences:

* The OpenSSL interface is designed with the idea the library is executed on a device which supports 8 bit, 32 bit and 64 bit registers. The hashcat crypto library is designed with the idea it is executed on a device which supports -only- 32 bit registers (like a GPU).
* The OpenSSL interface does not support the use of vector data types. This makes sense since in a typical use case scenario of OpenSSL there is no need to compute multiple keys based on multiple passwords at the same time. However, if we want to utilize special CPU instructions like SSE2, AVX2, XOP, etc. we need to write our code using vector data types. This enables the OpenCL runtime to do the translation. The hashcat crypto library therefore supports both scalar and vector data types as input data, but you need to use a different context data type. For instance, sha1_ctx_vector_t instead of sha1_ctx_t.

Working with the hashcat crypto libraries is straightforward. There are however some limitations you need to know about and you need to align with. The functions are designed to make it more easy for you to develop kernels, but they are written with performance in mind. This is achieved by using different optimization techniques. For instance, a crypto library cannot know how much data the user will provide. It therefore has to keep some buffers in the context to maintain some offsets. Each update() typically changes the buffer values and the offset. Typically you would code this by using some pointers. But pointers are poison for high performance. The computation of the address requires at least a temporary register, one or more mul() and another add() instruction call. This can be avoided. To do so, most of the code is using large switch() statements to enable the kernel compiler to translate a lot of code directly to register without the need to use an address to access a certain value in an array. But this goes too deep. Check `OpenCL/inc_common.cl` if you want to know more about the details.

The most important limits are the following:

* Functions are not converting data to the native endianness operation mode of whatever crypto primitive you are using. This is different to regular crypto libraries and can create a lot of headache if you are not used to this! You need to convert the data manually (typically just a hc_swap32() or hc_swap64() call). Keep in mind that all compute devices supported by OpenCL which I know of, operate in LE byte order. For instance, MD5 is using LE byte order. This means that you do not need to swap any data. However, SHA1 has a BE byte order and you need to convert the data. This is why it is so important to have a POC to verify intermediate result values.
* The buffer you provide must be padded to a size of a multiple of the block size of whatever crypto primitive you are using. For example 64 byte for MD5, SHA256, etc. and 128 byte for SHA512 and others. If you do not know the block sizes, check the algorithm specs. For instance, if you want to statically append a 5 byte string to a password from inside the kernel, you could use `sha1_update (&ctx, buf, 5);`, the important thing here is that buf[] must be declared as u32 buf[16]. That is because the block size of SHA1 is 64 byte.
* The buffer also needs to be zero padded. If only the first 5 byte of this 64 byte buffer is used, the remaining 59 bytes need to be set to zero.
* This goes back to how hashcat actually appends the data to the buffer in the context. Keep in mind, in OpenCL/CUDA there is no such thing as memcpy(). Of course you could write it yourself, but you will run into the performance problems explained above. Instead we are using switch(), followed by shifting the data to the final offset and then OR the temporary buffer to the existing buffer. This only works if the unused data is set to zero and the buffer has a known size.
* Shifting the buffer data changes the data. While you can reuse the buffer keep in mind you have to re-initialize the data. This is not the case if the buffers are global memory buffers.
* Note that none of the limitations are tested from the hashcat crypto library. You need to be careful or you will run into errors like out of boundary read/writes or have unexpected data.

Note that the type of buffer which holds the data is relevant, too. There are specific functions for working with local memory arrays and global memory arrays.

Often there is also a function which does the byte swapping for you. For instance, there is not only sha1_update() but there is also sha1_update_swap(). The prototypes are the same. There is also sha1_update_utf16le() and sha1_update_utf16le_swap(). I am sure you got the idea. If some helper function is missing, feel free to commit it to upstream but in a dedicated PR.

Since hashcat 6.0.0 it is also possible to use the hashcat crypto library from the host code. This is done by the emulation macros. To use a library, you just need to include `emu_inc_hash_sha1.h` or appropriate. Keep in mind that the limitations are exactly the same as if you use them from inside a kernel. A good example is `src/wordlist.c` or `src/modules/module_12600.c`.

## About Salts ##

In hashcat, we have two different types of salt structures. There is a fixed size data type and a generic size data type. This goes back to how hashcat was created and how it evolved over time. However, it turned out the concept still works very good even with the most complex algorithms of today.

### salt_t ###

The salt_t is a fixed size data type which is defined in `OpenCL/inc_types.cl` and holds a number of configuration settings and buffers with different meanings. However, they all are using 32 bit integers exclusively. This goes back to the fact that GPU registers are always 32 bit. You can work with 8 bit integers, but will make the GPU slower because it has to emulate an 8 bit register behavior (which is done transparently from your perspective). We however are trying to avoid this by sticking to u32 data type buffers for your entire kernel to achieve best performance. I will now explain the components of the salt_t structure in detail:

* u32 salt_buf[64]: This is the main buffer to store your salt in. The salt is limited to 64 times 32 bit (which is 4 bytes, 4 * 8 bits) elements, so 256 bytes. You need to guarantee that your salt buffer will never exceed 256 bytes, otherwise you can not store the salt in the salt_t structure. But for most cases, this is enough. If the salt buffer exceeds the 256 byte range, you need to use an esalt structure which is explained later.
* u32 salt_buf_pc[64]: This is an additional buffer to store precomputed values (typically based on the salt buffer). For instance, if you have an algorithm like sha1($p.md5($s)) you do not need to compute the md5($s) part for every try. It is enough to compute it once. The buffer is used to store the result of the md5($s) which you can access from within your kernel.
* u32 salt_len: This is just the length of the data stored in salt_buf[], in bytes. It is important that this value is also used during the salt buffer unique check on hashcat startup. Since the data stored as a salt is in binary, hashcat needs to know the length of this data to compare with other elements in the array. Keep this in mind and make sure to set a useful value, even if you are using a faked salt.
* u32 salt_len_pc: Same as salt_len but for the precomputed buffer. Set to 0 if there is no precomputed buffer, but keep in mind 0 is the default so in most cases you do not touch this.
* u32 salt_iter: This value holds the iteration count of your algorithm. This applies to slow hash kernels only and is used only in the _loop kernel. Note that some KDF (like PBKDF2) count their initialization round (in the _init kernel) as 1, thus you need to subtract 1 from the salt_iter count for this group of algorithms.
* u32 salt_iter2: Same as salt_iter, but for plugins which make use of a secondary loop kernel and which have set the option OPTS_TYPE_LOOP2.
* u32 salt_sign[2]: This option is most commonly used to recreate the original iteration count, salt buffer or even digest buffer set from a hash which is sometimes ambiguous. A good instance is DEScrypt, where there is a 64 bit digest encoded in an 11 byte base64 encoded string which results in 66 bit. Some applications do not zero the last 2 bits before encoding, resulting in multiple digest values for the same password. Since we need to store the real hash in our digest buffers we also need to save the remaining 2 bit in case the hash ever gets cracked and when we need to print the original hash to the console or output file.
* u32 digests_cnt: This value holds the number of digests which belong to this particular salt. After hashcat finishes decoding all the hashes from your hash file, it starts sorting and removing duplicates. At this time, it will also find possible multiple digest values which belong to the same salt. This allows hashcat to optimize the attack. This option is maintained by hashcat, do not modify it.
* u32 digests_done: This value holds the number of cracked digests which belong to a particular salt. If this number equals the number stored in digests_cnt, then hashcat knows it can remove this salt element for all upcoming kernel invocations. This speeds up the cracking process while hashcat is running. This option is maintained by hashcat, do not modify it.
* u32 digests_offset: This value keeps track of the information at which point in the digest buffer the sorted section of all the digests belonging to this particular salt starts. Since all digests, no matter which salt they belong to, are stored in one big array of u32 values we need to keep track of the starting point per unique salt. This value is important in the binary search which runs on the kernel. This option is maintained by hashcat, do not modify it.
* u32 scrypt_N: Some leftover for scrypt based algorithms from a time when there was no esalt. This option is maintained by hashcat, do not modify it.
* u32 scrypt_r: See scrypt_N.
* u32 scrypt_p: See scrypt_N.

### esalt ###

Of course there are also generic buffers in case the data of your hash mode simply covers additional data like encrypted data, IV, etc. or simply salt buffers which are too long to fit into the standardized salt_t structure. To define your own struct, you need to define it in the module as well as in the kernel. Since both source codes are independent from each other, you need to maintain them and guarantee that they are synchronized. The esalt buffers and structs in the corresponding `src/modules/` and `OpenCL/` plugin files need to be the same and any change in one of these esalt structs in one of these source files would need to be accompanied by a change of the other file too.  Other than that, it is a simple process. As described in the decoder section, hashcat needs to know the size of the structure so it can allocate enough memory space for it at the initialization phase. In order to inform the hashcat host binary of the esalt size, you must provide it via the function module_esalt_size(). It could be either a maximum size (upper limit) or a constant size. This depends on the algorithm.
That is all. You can now cast the void *esalt_buf which is provided to you in the decoder and encoder functions to your esalt structure type. Note this address is maintained by hashcat. It guarantees a fresh buffer for each invocation of module_hash_decode(). Therefore, you can simply cast it for instance like this:

```
wpa_eapol_t *wpa_eapol = (wpa_eapol_t *) esalt_buf;
```

You can access the esalt from the encoder function and read the data the exact same way by casting it to your esalt struct.

Important: No matter if you are going to use an esalt or not, you always need to fill the salt_buf[] array and set the salt_len for it.

Important: In case you write a slow hash, you need to set the salt_iter element. Also never forget to implement module_esalt_size() if you use an esalt.

## Data Structures: salt_t vs esalt ##

Hashcat has a generic data structure to handle "easy" salts (salt_t) and an open data structure one, that you can define yourself in case the generic data structure does not fit your needs (esalt). An "easy" salt is a single buffer salt of less than 256 byte (can be binary). The open data structure is called "esalt".

It is important to understand the difference between the generic salt_t struct and the esalt struct (which you create on your own). In fact it is essential to distinguish them. Based on the data we assign to the salt_t struct, hashcat sorts and groups all digests belonging to this particular salt_t first by the salt buffer content in salt->salt_buf[]. We can see it as a top level grouping. With the data we assign to the esalt, hashcat sorts and groups all hashes, but on a level below. Like in a SQL Statement when we do something like:

`SELECT digest FROM hashes GROUP BY salt_t,esalt`

But why is that? It is an optimization. If we have different data stored in salt_t and esalt, hashcat expects us to access salt_t data in the _init kernel and expects us to access the data of our esalt only from the _comp kernel. But that is an optional step and probably something of which you did not think of if you never wrote a hashcat plugin before.

A good example is the WPA mode. The crypto scheme in this mode requires multiple salt fields (IVs, mac addresses, encrypted data, etc). To derive the PMK master key (the slow part in the algorithms), only the ESSID (the network name) is required. If we want to crack WPA, typically we capture multiple handshakes, however all handshakes could be belonging to the same network. If we are clever we can exploit this weakness. In the parser we would set only the ESSID in the salt_t struct and all other data (IV, MAC addresses, etc.) go into the esalt. By doing so, hashcat will only spawn that many _init and _loop kernels as there are unique ESSIDs in the generic salt_t buffers. If we have captured 100 handshakes of the same network, hashcat only needs to run the compute intensive _loop kernel one time, not 100 times. But how to use the _comp kernel in this case?

Now let us talk about the three different types of _comp kernels. The first type is if we have an easy crypto algorithm which only contains a single salt buffer in the salt_t struct. Imagine we have ten real hashes but they all share the same salt. In such a case there is still no need to run the _init and the slow _loop kernel ten times. A single invocation of both is enough. In the _comp kernel hashcat will search a database if the digest exists in a database which is important. We only need to search this database for the existence of the hash, we do not need to decrypt something. This database is created automatically by hashcat at the very start. Every digest which we assign to the digest_t struct will be sorted and stored inside this database. Inside the _comp kernel, if we assign the final digest to r0 - r4 and call the #include COMPARE_M macro, the database gets searched. This code is highly optimized and is using a bloom filter and an additional binary tree search. So it can handle millions of hashes very efficiently. See `OpenCL/m00500-pure.cl` as an easy example.

Sometimes this is not enough. For instance, if we do not have a final digest which we could search for "existence" in the database. This happens if we have to decrypt some data and match the content of the decrypted data against some known pattern. It is obvious if we match data in this case we can not search the data for existence, right? In this case we actually need to iterate through all entries in the database. This is something very irregular from the general hashcat concept but there is a way to deal with it. Of course, if you only support single targets this is not a problem. The recommended way to deal with this is to verify if the salt_buf data you are using is unique. The goal is to force hashcat to call the _comp kernel as many times as it loads unique hashes from your hash list and iterates through all of them individually. If we choose to use this mode, it is essential for the salt_t buffer to be exactly as unique as the esalt buffer (the same number of entries). This could be achieved by using parts of encrypted data and copying it to salt->salt_buf[]. Hashcat will be forced to increment the `digests_offset` variable for each iteration which gives you the opportunity to index the different hashes individually. A good example for such a _comp kernel can be found in `OpenCL/m14700-pure.cl`.

There is even a third mode which is close to the second mode, but does not have the disadvantage of syncing the salt_t with the esalt, giving you the opportunity to exploit salt specific vulnerabilities in the algorithm (like in WPA). This mode can be activated by setting OPTS_TYPE_DEEP_COMP_KERNEL flag in the module. In this case hashcat will know that it has to call the _comp kernel for that many entries that are bound to a unique salt_t entry. So far there are only two algorithms which make use of that. This mode should therefore only be used in very rare cases and is discouraged if not applicable. See `OpenCL/m22000-pure.cl` as an example.

Most kernels today go for the second mode. However, if possible we should use the first mode because it is much more elegant. There is a trick to step down from the second mode to the first mode. In case we need to match some data after decryption but we know 100% of the data it is better to encrypt the known plaintext data instead of decrypting the encrypted data. In this case our final value can be searched in a database for "existence" and we can operate in first mode (i.e. make a "lookup").

## Tokenizer ##

The tokenizer is basically a CSV parser but with some special features. When it comes to loading hash files it is sometimes not so easy. The hash files often have been generated by extraction tools which do not follow CSV rules very carefully. Often the CSV is broken because of missing escape characters, quotation or other problems. Additionally, the tokenizer covers a preliminary data sanitization and data length check.

Of course we could have used a regular expression engine to do the same. But if you think of the potential multi million hash entries in hash files the tokenizer is much faster than a regular expression. Also the tokenizer offers configuration items that are known to be relevant when it comes to parsing hashes. The configuration of the tokenizer is very easy to read for third parties and gives an easy overview of how the hash lines are separated from a standardized perspective.

One very unique feature is that the tokenizer allows you to have both dynamic length columns and fixed length columns in the same hash line. This is sometimes the only way to read a hash line. Another unique feature is that it allows you to change the separator character for different columns in the same hash line. This is why you have to specify the separator character for each column separately.

The first step after declaring the tokenizer context buffer is to create its configuration. There is just one mandatory parameter and a maximum of 128 optional configuration items (columns). The mandatory configuration item needs to be set to the number of columns/fields which the hash line includes. Note that this is a fixed value. For more complex hash lines with a dynamic column count you need to create multiple tokenizer instances (e.g. use a second configuration, if the first one failed), but in most of the times this is not required.

```
hc_token_t token;

token.token_cnt = 1;
```

For a very simple, unsalted hash there is just one column: the hash. If this is a MD5 hash, it is typically encoded as a hex string of exact size 32 byte. These properties we can configure for the first column:

```
token.len_min[0] = 32;
token.len_max[0] = 32;
token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                 | TOKEN_ATTR_VERIFY_HEX;
```

The parameters len_min and len_max always define a valid range in bytes. Since it is always 32 byte, we simply set 32 to both parameters. With the configuration item `TOKEN_ATTR_VERIFY_LENGTH` we inform the tokenizer to verify the data length. If the length does not match, we will refuse the hash. The same goes for the configuration item `TOKEN_ATTR_VERIFY_HEX`. As you can imagine, this informs the tokenizer to verify if the data contains only hex characters (no matter the case). For more verification configuration items please see `includes/types.h`.

Finally the tokenizer is called. If any of the verification configuration items do not pass, the tokenizer will return a specific error code. As always, the error codes can be found in `includes/types.h`.

```
const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);
```

If everything went well up to this point, the tokenizer has placed the pointer addresses for the start to each of the columns in the token.buf[] array and the corresponding length in the token.len[] array. For instance, if there is only one column, the pointer address in token.buf[0] will be populated as well as token.len[0]. If you have two columns (token_cnt = 2), there will also be token.buf[1] and token.len[1], and so on.

As always, you can use the tokenizer configurations in the existing modules as a reference, especially for complex hash lines.

For hash lines with multiple columns, we need to use for each column either TOKEN_ATTR_FIXED_LENGTH (see below) or configure the separator character. The separator has to be a single byte character and is set using the "sep" parameter.

```
token.sep[0]     = ':';
token.len_min[0] = 32;
token.len_max[0] = 32;
token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                 | TOKEN_ATTR_VERIFY_HEX;

token.len_min[1] = 0;
token.len_max[1] = 32;
token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;
```

In the above example you can see that we have hard-coded the separator character to ':'. In addition, this type of configuration the tokenizer will refuse the hash line if the separator was not found. You can also use the hashconfig->separator character if you want to use the separator character the hashcat user set using the -p command line option (default being ':').

There is one more configuration item which I want to describe:

* TOKEN_ATTR_FIXED_LENGTH: This is for columns of which you know the exact length -and- which are not followed by a separator character. In this case you do not need to set the parameters "len_min" and "len_max", but you need to set the parameter "len" instead. This is a typical pitfall if you copy/paste configuration settings from other modules and switch from a dynamic length to a fixed length. Do not forget to also change the parameter name ("len_min"/"len_max" instead of just "len") and the indices.

