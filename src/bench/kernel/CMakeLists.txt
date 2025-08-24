# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_executable(bench_kernel
    kernel_block_serialize.cpp
    ../bench.cpp
    ../nanobench.cpp
    ../bench_bitcoin.cpp
)

include(TargetDataSources)
target_raw_data_sources(bench_kernel NAMESPACE benchmark::data
  ../data/block911451.raw
)

target_link_libraries(bench_kernel
  test_util
  bitcoin_node
  bitcoinkernel
)