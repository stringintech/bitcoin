#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ExampleRegtestReorg(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Set mocktime for deterministic block generation")
        node.setmocktime(node.getblockheader(node.getbestblockhash())['time'])

        self.log.info("Generate 3 blocks")
        for i in range(3):
            self.generate_one_block()
        assert_equal(node.getblockcount(), 3)

        self.log.info(f"Invalidating block at height 2")
        node.invalidateblock(node.getblockhash(2))
        assert_equal(node.getblockcount(), 1)

        self.log.info("Generate 3 new blocks on the alternative chain (fork from block 1)")
        for i in range(3):
            self.generate_one_block()
        assert_equal(node.getblockcount(), 4)

    def generate_one_block(self):
        node = self.nodes[0]
        node.bumpmocktime(1)
        block_hash = self.generate(node, nblocks=1, sync_fun=self.no_op)[0]
        block_height = node.getblockcount()
        block_hex = node.getblock(block_hash, 0)

        self.log.info(f"New block generated:")
        self.log.info(f"  Height: {block_height}")
        self.log.info(f"  Hash: {block_hash}")
        self.log.info(f"\n=== BLOCK FULL HEX ===")
        self.log.info(block_hex + "\n\n")

if __name__ == '__main__':
    ExampleRegtestReorg(__file__).main()