// Ground-truth fixture: a deliberate one-element out-of-bounds __global__
// write. Verified during planning to produce a real
// "Invalid __global__ write" finding under `compute-sanitizer --tool memcheck`.
#include <cstdio>

__global__ void oob_write_kernel(int *buf, int n)
{
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    buf[idx + 1] = idx; // writes one element past the allocated array
}

int main()
{
    int *d_buf;
    int n = 32;
    cudaMalloc(&d_buf, n * sizeof(int));
    oob_write_kernel<<<1, n>>>(d_buf, n);
    cudaDeviceSynchronize();
    cudaFree(d_buf);
    printf("done\n");
    return 0;
}
