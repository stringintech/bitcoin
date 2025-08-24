// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <bench/data/block911451.raw.h>
#include <kernel/bitcoinkernel_wrapper.h>

static void KernelBlockSerialize(benchmark::Bench& bench)
{
    btck::Block block{benchmark::data::block911451};
    bench.minEpochIterations(10).run([&] {
        auto bytes = block.ToBytes();
    });
}

static void KernelBlockSerializePeAlloc(benchmark::Bench& bench)
{
    btck::Block block{benchmark::data::block911451};
    bench.minEpochIterations(10).run([&] {
        auto bytes = block.ToPreAllocBytes();
    });
}

BENCHMARK(KernelBlockSerialize, benchmark::PriorityLevel::HIGH);
BENCHMARK(KernelBlockSerializePeAlloc, benchmark::PriorityLevel::HIGH);