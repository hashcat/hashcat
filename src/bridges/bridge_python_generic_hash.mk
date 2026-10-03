# The bridge starts an interpreter as a separate process and talks to it over a pipe, so it needs no
# Python headers and no Python library. cpu_features.c is the one source it adds, for the check every
# bridge makes that the CPU supports what the plugin was compiled for.

BRIDGE_SRC_bridge_python_generic_hash := src/bridges/bridge_python_generic_hash.c src/cpu_features.c
