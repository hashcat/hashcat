// Ground-truth fixture: a deliberate one-element out-of-bounds __global__
// read (read-side twin of oob_write.cu).
#include <cstdio>

__global__ void oob_read_kernel(const int *buf, int *out, int n)
{
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    out[idx] = buf[idx + 1]; // reads one element past the allocated array
}

int main()
{
    int *d_buf, *d_out;
    int n = 32;
    cudaMalloc(&d_buf, n * sizeof(int));
    cudaMalloc(&d_out, n * sizeof(int));
    cudaMemset(d_buf, 0, n * sizeof(int));
    oob_read_kernel<<<1, n>>>(d_buf, d_out, n);
    cudaDeviceSynchronize();
    cudaFree(d_buf);
    cudaFree(d_out);
    printf("done\n");
    return 0;
}
