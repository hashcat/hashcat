##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Builds tools/rule_lookup, which answers which word and which rule of an "-a 0 wordlist -r rules"
# attack produce a given candidate. Run it from the repository root, after make:
#
#   make -f tools/rule_lookup.mk
#   make -f tools/rule_lookup.mk clean
#
# It links libhashcat, so that the rule engine it applies is hashcat's own rather than a second
# implementation of the rule language. src/rp.c is compiled in for cpu_rule_to_kernel_rule (), which
# turns a written rule into the form the engines take and is not exported by the library.

RULE_LOOKUP      := tools/rule_lookup
RULE_LOOKUP_SRC  := tools/rule_lookup.c src/rp.c
RULE_LOOKUP_LIB  := libhashcat.so.7

CC               ?= gcc
CFLAGS_LOOKUP    := -std=gnu99 -W -Wall -Wextra -O2 -Iinclude/ -IOpenCL/ -Ideps/OpenCL-Headers
LDFLAGS_LOOKUP   := -lpthread -lm -ldl -lrt -Wl,-rpath,'$$ORIGIN/..'

.PHONY: all clean

all: $(RULE_LOOKUP)

$(RULE_LOOKUP): $(RULE_LOOKUP_SRC) $(RULE_LOOKUP_LIB)
	$(CC) $(CFLAGS_LOOKUP) $(RULE_LOOKUP_SRC) $(RULE_LOOKUP_LIB) -o $@ $(LDFLAGS_LOOKUP)

$(RULE_LOOKUP_LIB):
	@echo "$(RULE_LOOKUP_LIB) is missing. Run make first, this links against the library it builds."
	@false

clean:
	rm -f $(RULE_LOOKUP)
