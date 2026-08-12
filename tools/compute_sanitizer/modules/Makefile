NVCC := $(shell command -v nvcc 2>/dev/null || echo /usr/local/cuda/bin/nvcc)

SRCS := $(wildcard *.cu)
BINS := $(SRCS:.cu=)

all: $(BINS)

%: %.cu
	$(NVCC) -lineinfo -o $@ $<

clean:
	rm -f $(BINS)

.PHONY: all clean
