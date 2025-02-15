#!/usr/bin/env python3

from decimal import Decimal
from stringintech_mempool_eviction_tests_base import MempoolEvictionTestBase
from test_framework.messages import COIN


class PackageEvictionTest(MempoolEvictionTestBase):
    def set_test_params(self):
        super().set_test_params()

    def run_test(self):
        node = self.nodes[0]

        tx_break = self.create_break_tx()
        tx_a, tx_b, tx_c, tx_d, tx_e = self.create_transaction_tree()
        self.fill_mempool(tx_break)

        eviction_tx = self.wallet.send_self_transfer(
            from_node=node,
            target_vsize=90000,
            fee=Decimal(1000000 / COIN)
        )

        mempool = node.getrawmempool()
        assert tx_a['txid'] not in mempool, "Transaction A should be evicted"
        assert tx_b['txid'] not in mempool, "Transaction B should be evicted"
        assert tx_c['txid'] not in mempool, "Transaction C should be evicted"
        assert tx_d['txid'] not in mempool, "Transaction D should be evicted"
        assert tx_e['txid'] not in mempool, "Transaction E should be evicted"
        assert eviction_tx['txid'] in mempool, "Eviction transaction should be in mempool"


if __name__ == '__main__':
    PackageEvictionTest(__file__).main()
