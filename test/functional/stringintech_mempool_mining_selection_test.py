#!/usr/bin/env python3

from stringintech_mempool_eviction_tests_base import MempoolEvictionTestBase


class MiningSelectionTest(MempoolEvictionTestBase):
    def set_test_params(self):
        super().set_test_params()

    def run_test(self):
        node = self.nodes[0]

        tx_break = self.create_break_tx()
        tx_a, tx_b, tx_c, tx_d, tx_e = self.create_transaction_tree()
        self.fill_mempool(tx_break)

        blocks = self.generate(self.wallet, 6)
        txids = []
        for b in blocks:
            block = node.getblock(blockhash=b, verbosity=3)
            block_txids = [tx['txid'] for tx in block['tx']]
            self.log.info(f"{len(block_txids)} new txs mined")
            txids.extend(block_txids)

        assert txids[1] == tx_a['txid'], "Transaction A should be mined first"
        assert txids[2] == tx_e['txid'], "Transaction E should be mined second"


if __name__ == '__main__':
    MiningSelectionTest(__file__).main()
