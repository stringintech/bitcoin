# Benchmarks

## Block Serialization Benchmark

**File:** `kernel_block_serialize.cpp`

**What it compares:**
Two different approaches to serializing blocks to bytes using the Bitcoin Kernel API:

1. **ToBytes()** - Uses growing vector with dynamic allocations
2. **ToPreAllocBytes()** - Pre-allocates vector using `btck_block_get_serialize_size()` C API

### Running the Benchmark

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_BENCH=ON -DBUILD_KERNEL_LIB=ON
cmake --build build
./build/bin/bench_kernel
```

### Sample Results

```
|               ns/op |                op/s |    err% |     total | benchmark
|--------------------:|--------------------:|--------:|----------:|:----------
|          841,526.55 |            1,188.32 |    0.3% |      0.10 | `KernelBlockSerialize`
|          830,366.70 |            1,204.29 |    0.1% |      0.10 | `KernelBlockSerializePeAlloc`
```

- **CPU performance**: ~1.3% improvement with pre-allocation (841,527 → 830,367 ns/op)
- **Throughput**: Increased from 1,188 to 1,204 operations/second