#!/usr/bin/env python3
"""Generate test data for P2SH timelock transactions (CLTV and CSV).

Redeem script patterns (pre-segwit P2SH):
    CLTV: <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG
    CSV:  <sequence> OP_CHECKSEQUENCEVERIFY OP_DROP <pubkey> OP_CHECKSIG
"""

import random

from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import (
    CTransaction,
    CTxIn,
    CTxOut,
    COutPoint,
)
from test_framework.script import (
    CScript,
    CScriptNum,
    OP_CHECKSIG,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_DROP,
    OP_TRUE,
    sign_input_legacy,
)
from test_framework.script_util import script_to_p2sh_script
from test_framework.wallet import MiniWallet, MiniWalletMode
from test_framework.wallet_util import generate_keypair


class GenerateTimelockTestData(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-acceptnonstdtxn=1']]

    def run_test(self):
        random.seed(42)  # makes generate_keypair() deterministic
        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_OP_TRUE)
        # Mine enough blocks to mature coinbase so the wallet has outputs to spend
        self.generate(wallet, 100)

        self._run_cltv(wallet)
        self._run_csv(wallet)

    def _run_cltv(self, wallet):
        privkey, pubkey = generate_keypair()

        locktime = 100
        redeem_script = CScript([CScriptNum(locktime), OP_CHECKLOCKTIMEVERIFY, OP_DROP, pubkey, OP_CHECKSIG])
        p2sh_scriptpubkey = script_to_p2sh_script(redeem_script)

        amount_satoshis = 100_000_000
        fund = wallet.send_to(from_node=self.nodes[0], scriptPubKey=p2sh_scriptpubkey, amount=amount_satoshis)

        funding_txid_int = int(fund['txid'], 16)
        funding_vout = fund['sent_vout']
        dest_scriptpubkey = CScript([OP_TRUE])

        tx_pass = CTransaction()
        tx_pass.version = 2
        tx_pass.vin = [CTxIn(COutPoint(funding_txid_int, funding_vout), nSequence=0)]
        tx_pass.vout = [CTxOut(amount_satoshis - 1000, dest_scriptpubkey)]
        tx_pass.nLockTime = 100
        tx_pass.vin[0].scriptSig = CScript([redeem_script])
        sign_input_legacy(tx_pass, 0, redeem_script, privkey)

        tx_fail = CTransaction()
        tx_fail.version = 2
        tx_fail.vin = [CTxIn(COutPoint(funding_txid_int, funding_vout), nSequence=0)]
        tx_fail.vout = [CTxOut(amount_satoshis - 1000, dest_scriptpubkey)]
        tx_fail.nLockTime = 50  # does NOT satisfy CLTV requirement of 100
        tx_fail.vin[0].scriptSig = CScript([redeem_script])
        sign_input_legacy(tx_fail, 0, redeem_script, privkey)

        self.log.info(f"CLTV scriptPubKey: {p2sh_scriptpubkey.hex()}")
        self.log.info(f"CLTV pass tx: {tx_pass.serialize().hex()}")
        self.log.info(f"CLTV fail tx: {tx_fail.serialize().hex()}")

    def _run_csv(self, wallet):
        privkey, pubkey = generate_keypair()

        sequence = 10
        redeem_script = CScript([CScriptNum(sequence), OP_CHECKSEQUENCEVERIFY, OP_DROP, pubkey, OP_CHECKSIG])
        p2sh_scriptpubkey = script_to_p2sh_script(redeem_script)

        amount_satoshis = 100_000_000
        fund = wallet.send_to(from_node=self.nodes[0], scriptPubKey=p2sh_scriptpubkey, amount=amount_satoshis)

        funding_txid_int = int(fund['txid'], 16)
        funding_vout = fund['sent_vout']
        dest_scriptpubkey = CScript([OP_TRUE])

        tx_pass = CTransaction()
        tx_pass.version = 2
        tx_pass.vin = [CTxIn(COutPoint(funding_txid_int, funding_vout), nSequence=10)]
        tx_pass.vout = [CTxOut(amount_satoshis - 1000, dest_scriptpubkey)]
        tx_pass.nLockTime = 0
        tx_pass.vin[0].scriptSig = CScript([redeem_script])
        sign_input_legacy(tx_pass, 0, redeem_script, privkey)

        tx_fail = CTransaction()
        tx_fail.version = 2
        tx_fail.vin = [CTxIn(COutPoint(funding_txid_int, funding_vout), nSequence=5)]  # does NOT satisfy CSV requirement of 10
        tx_fail.vout = [CTxOut(amount_satoshis - 1000, dest_scriptpubkey)]
        tx_fail.nLockTime = 0
        tx_fail.vin[0].scriptSig = CScript([redeem_script])
        sign_input_legacy(tx_fail, 0, redeem_script, privkey)

        self.log.info(f"CSV scriptPubKey: {p2sh_scriptpubkey.hex()}")
        self.log.info(f"CSV pass tx: {tx_pass.serialize().hex()}")
        self.log.info(f"CSV fail tx: {tx_fail.serialize().hex()}")


if __name__ == '__main__':
    GenerateTimelockTestData(__file__).main()