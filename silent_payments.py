import hashlib
from typing import List, TYPE_CHECKING
from electrum import ecc
from electrum.transaction import PartialTransaction, PartialTxInput
from electrum.bitcoin import script_to_p2tr

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet

class SilentPaymentEngine:
    @staticmethod
    def get_input_privkeys_sum(tx: PartialTransaction, wallet: 'Abstract_Wallet') -> int:
        """
        Sums the private keys of all inputs eligible for IFSSD 
        (Inputs For Shared Secret Derivation).
        """
        total_privkey_scalar = 0
        for txin in tx.inputs():
            # Only use inputs that we can sign for (IFSSD)
            if not wallet.can_sign(txin):
                continue
                
            privkey_bytes, is_compressed = wallet.export_private_key(txin.address, None)
            scalar = int.from_hex(privkey_bytes.hex())
            
            # BIP 352: For P2TR inputs, ensure even Y parity (negate if odd)
            if txin.is_taproot():
                pubkey_bytes = ecc.get_public_key_from_private_key(privkey_bytes)
                if pubkey_bytes[0] == 0x03: # Odd parity
                    scalar = ecc.generator_order() - scalar
            
            total_privkey_scalar = (total_privkey_scalar + scalar) % ecc.generator_order()
            
        return total_privkey_scalar

    @staticmethod
    def calculate_outpoints_hash(tx: PartialTransaction) -> bytes:
        """
        BIP 352: hashBIP0352/Inputs(outpointL || A)
        where outpointL is the lexicographically smallest outpoint.
        """
        # Collect and sort outpoints (txid + vout)
        outpoints = []
        for txin in tx.inputs():
            outpoints.append(txin.prevout.serialize_to_network())
        outpoints.sort()
        
        # We only need the smallest outpoint for the hash in v0
        smallest_outpoint = outpoints[0]
        return hashlib.sha256(smallest_outpoint).digest()

    @staticmethod
    def tweak_transaction_outputs(tx: PartialTransaction, wallet: 'Abstract_Wallet'):
        """
        The main entry point called by the 'before_create_transaction' hook.
        """
        # 1. Sum input private keys (a)
        sum_a = SilentPaymentEngine.get_input_privkeys_sum(tx, wallet)
        if sum_a == 0:
            raise ValueError("No eligible inputs for Silent Payment derivation.")

        # 2. Get outpoints hash
        input_hash = SilentPaymentEngine.calculate_outpoints_hash(tx)
        
        # 3. Process each tagged SP output
        for i, out in enumerate(tx.outputs()):
            if not getattr(out, 'is_sp', False):
                continue
            
            # Parse SP address (Bscan || Bspend)
            # Address data is 66 bytes: 33 for Bscan, 33 for Bspend
            sp_data = decode_bech32m(out.sp_address) 
            b_scan_bytes = sp_data[:33]
            b_spend_bytes = sp_data[33:]
            
            # 4. ECDH Shared Secret: s = input_hash * a * Bscan
            # We use a * input_hash as the scalar
            scalar_t = (sum_a * int.from_bytes(input_hash, 'big')) % ecc.generator_order()
            shared_secret_point = ecc.ECPubkey(b_scan_bytes) * scalar_t
            
            # 5. Calculate Final Tweak: tk = hash(serP(shared_secret) || k)
            k = 0 # Incremented per recipient in the same transaction
            hasher = hashlib.sha256()
            hasher.update(shared_secret_point.get_public_key_bytes(compressed=True))
            hasher.update(k.to_bytes(4, 'big'))
            tk = hasher.digest()
            
            # 6. Tweak Spend Key: P = Bspend + tk * G
            tweaked_pubkey = ecc.ECPubkey(b_spend_bytes) + (int.from_bytes(tk, 'big') * ecc.generator())
            
            # 7. Convert to P2TR script
            x_only_pubkey = tweaked_pubkey.get_public_key_bytes(compressed=True)[1:]
            out.scriptpubkey = script_to_p2tr(x_only_pubkey)