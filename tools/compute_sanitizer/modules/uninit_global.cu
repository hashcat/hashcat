// Ground-truth fixture: reads a cudaMalloc'd buffer that was never
// initialized. Intended for the `initcheck` tool (uninitialized device
// memory), not `memcheck` (which only checks addressability, not init state).
#include <cstdio>

__global__ void uninit_read_kernel(const int *buf, int *out, int n)
{
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    if (idx < n) out[idx] = buf[idx]; // buf was never written on the host or device side
}

int main()
{
    int *d_buf, *d_out;
    int n = 32;
    cudaMalloc(&d_buf, n * sizeof(int));  // deliberately never initialized
    cudaMalloc(&d_out, n * sizeof(int));
    cudaMemset(d_out, 0, n * sizeof(int));
    uninit_read_kernel<<<1, n>>>(d_buf, d_out, n);
    cudaDeviceSynchronize();
    cudaFree(d_buf);
    cudaFree(d_out);
    printf("done\n");
    return 0;
}
