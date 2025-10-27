#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import subprocess

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

class BitcoinChainstateTest(BitcoinTestFramework):
    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_chainstate()

    def set_test_params(self):
        """Use the pregenerated, deterministic chain up to height 199."""
        self.num_nodes = 2
        self.extra_args = [[],[]]

    def setup_network(self):
        """Start with the nodes disconnected so that one can generate a snapshot
        including blocks the other hasn't yet seen."""
        self.add_nodes(2)
        self.start_nodes(extra_args=self.extra_args)

    def run_test(self):
        n0 = self.nodes[0]
        n1 = self.nodes[1]

        # nodes are disconnected; n0 mines some blocks until reaches
        # the snapshot height while n1 unaware of them
        self.mini_wallet = MiniWallet(n0)
        for n in self.nodes:
            n.setmocktime(n.getblockheader(n.getbestblockhash())['time'])
        for i in range(100):
            block_tx = 1
            if i % 3 == 0:
                self.mini_wallet.send_self_transfer(from_node=n0)
                block_tx += 1
            self.generate(n0, nblocks=1, sync_fun=self.no_op)
        assert_equal(n0.getblockcount(), 299)
        assert_equal(n0.getbestblockhash(), "7cc695046fec709f8c9394b6f928f81e81fd3ac20977bb68760fa1faa7916ea2") # hardcoded in regtest chainparams
        assert_equal(n1.getblockcount(), 199)
        dump_output = n0.dumptxoutset('utxos.dat', "latest")

        # n1 should know about the headers to activate the snapshot
        for i in range(1, 300):
            block = n0.getblock(n0.getblockhash(i), 0)
            n1.submitheader(block)
        loaded = n1.loadtxoutset(dump_output['path'])
        assert_equal(loaded['base_height'], 299)
        datadir = n1.cli.datadir
        n1.stop_node()

        # n0 mines a new block which should extend the n1 snapshot chain later
        self.generate(n0, nblocks=1, sync_fun=self.no_op)
        new_best_block = n0.getblock(n0.getbestblockhash(), 0)
        n0.stop_node()
        self.add_block(datadir, new_best_block, "Block extended best chain")

    def add_block(self, datadir, input, expected_stderr):
        proc = subprocess.Popen(
            self.get_binaries().chainstate_argv() + [datadir],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate(input=input + "\n", timeout=5)
        self.log.debug("STDOUT: {0}".format(stdout.strip("\n")))
        self.log.info("STDERR: {0}".format(stderr.strip("\n")))

        if expected_stderr not in stderr:
            raise AssertionError(f"Expected stderr output {expected_stderr} does not partially match stderr:\n{stderr}")


if __name__ == "__main__":
    BitcoinChainstateTest(__file__).main()
