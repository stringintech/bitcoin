#!/usr/bin/env python3

from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import COIN
from test_framework.wallet import MiniWallet


class MempoolEvictionTestBase(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [
            [
                "-datacarriersize=100000",
                "-maxmempool=5",
            ],
            # second node has default mempool parameters
            [
            ],
        ]
        self.supports_cli = False

    def run_test(self):
        """Base run_test implementation that must be overridden by child classes."""
        raise NotImplementedError("Child classes must implement run_test")

    def setup_chain(self):
        super().setup_chain()

    def setup_network(self):
        super().setup_network()
        self.wallet = MiniWallet(self.nodes[0])

    def create_break_tx(self):
        tx_break = self.wallet.send_self_transfer_multi(
            from_node=self.nodes[0],
            num_outputs=1000
        )
        self.generate(self.wallet, 1)
        return tx_break

    def create_transaction_tree(self):
        node = self.nodes[0]
        tx_a = self.wallet.send_self_transfer_multi(
            from_node=node,
            num_outputs=3,
            target_vsize=250,
            fee_per_output=250 // 3
        )

        tx_b = self.wallet.send_self_transfer(
            from_node=node,
            utxo_to_spend=tx_a['new_utxos'][0],
            target_vsize=50000,
            fee=Decimal(50000 / COIN)
        )

        tx_c = self.wallet.send_self_transfer(
            from_node=node,
            utxo_to_spend=tx_a['new_utxos'][1],
            target_vsize=50000,
            fee=Decimal(50000 / COIN)
        )

        tx_d = self.wallet.send_self_transfer_multi(
            from_node=node,
            utxos_to_spend=[tx_b['new_utxo'], tx_c['new_utxo']],
            target_vsize=500,
            fee_per_output=52000,
            num_outputs=1,
        )

        tx_e = self.wallet.send_self_transfer(
            from_node=node,
            utxo_to_spend=tx_a['new_utxos'][2],
            target_vsize=250,
            fee=Decimal(49750 / COIN)
        )

        self.log_fee_rates(tx_a, tx_b, tx_c, tx_d, tx_e)
        return tx_a, tx_b, tx_c, tx_d, tx_e

    def fill_mempool(self, tx_break):
        node = self.nodes[0]
        i = 0
        current_info = node.getmempoolinfo()
        while current_info["maxmempool"] - current_info["bytes"] > 100000:
            self.wallet.send_self_transfer(
                from_node=node,
                utxo_to_spend=tx_break['new_utxos'][i],
                fee=Decimal(400000 / COIN),
                target_vsize=100000
            )
            current_info = node.getmempoolinfo()
            i += 1

    def log_fee_rates(self, tx_a, tx_b, tx_c, tx_d, tx_e):
        """Log ancestor and descendant fee rates for the transaction tree."""

        entries = {
            'A': self.nodes[0].getmempoolentry(tx_a['txid']),
            'B': self.nodes[0].getmempoolentry(tx_b['txid']),
            'C': self.nodes[0].getmempoolentry(tx_c['txid']),
            'D': self.nodes[0].getmempoolentry(tx_d['txid']),
            'E': self.nodes[0].getmempoolentry(tx_e['txid'])
        }

        for tx_name, entry in entries.items():
            ancestor_rate, descendant_rate = self.calculate_fee_rates(entry)
            self.log.info(f"Tx {tx_name} - Ancestor feerate: {ancestor_rate:.2f}, Descendant feerate: {descendant_rate:.2f}")

    @staticmethod
    def calculate_fee_rates(entry):
        """
        Calculate ancestor and descendant fee rates for a transaction entry.

        Args:
            entry (dict): Transaction entry containing size and fee information

        Returns:
            tuple: (ancestor_fee_rate, descendant_fee_rate) in sats/byte
        """
        ancestor_fee_rate = float(entry['fees']['ancestor']) * 100000000 / entry['ancestorsize']
        descendant_fee_rate = float(entry['fees']['descendant']) * 100000000 / entry['descendantsize']

        return ancestor_fee_rate, descendant_fee_rate