from typing import TYPE_CHECKING
from PyQt6.QtCore import pyqtSignal

from electrum.plugin import BasePlugin, hook
from electrum.i18n import _
from electrum.util import show_error
from electrum.transaction import PartialTransaction

from .silent_payments import SilentPaymentEngine
from .transaction_utils import is_silent_payment_output, calculate_integrity_hash
from PyQt6.QtWidgets import QVBoxLayout, QLabel, QComboBox, QDialog, QDialogButtonBox
from electrum.gui.qt.util import WindowModalDialog, Buttons, CloseButton

if TYPE_CHECKING:
    from electrum.gui.qt.main_window import ElectrumWindow
    from electrum.wallet import Abstract_Wallet

class Plugin(BasePlugin):
    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)

    @hook
    def before_send(self, window: 'ElectrumWindow', outputs):
        """
        Intercepts the Send tab output list. 
        Validates sp1... addresses and prepares them for the wallet.
        """
        for out in outputs:
            if out.address.startswith('sp1'):
                if not SilentPaymentEngine.is_valid_address(out.address):
                    show_error(_("Invalid Silent Payment address"))
                    return False
                
                # Tag the output object so our other hooks recognize it
                out.is_sp = True
                out.sp_address = out.address
                
                # Assign a dummy scriptPubKey so Electrum can perform coin selection
                # We use a standard P2TR length (34 bytes)
                out.scriptpubkey = b'\x51\x20' + b'\x00' * 32

    @hook
    def before_create_transaction(self, wallet: 'Abstract_Wallet', tx: PartialTransaction):
        """
        Calculates the actual BIP 352 tweaks once inputs are selected.
        """
        sp_outputs = [out for out in tx.outputs() if getattr(out, 'is_sp', False)]
        if not sp_outputs:
            return

        # BIP 352 requires SIGHASH_ALL and no RBF for safety
        tx.set_rbf(False)

        try:
            # The engine uses the private keys of the selected inputs
            # to derive the shared secret for each recipient.
            SilentPaymentEngine.tweak_transaction_outputs(tx, wallet)
            
            # Add an integrity hash to the transaction metadata
            # This ensures the tweak remains valid during the signing phase.
            tx.extra_hashes['sp_integrity'] = calculate_integrity_hash(tx)
            
        except Exception as e:
            self.logger.error(f"Failed to tweak SP outputs: {e}")
            show_error(_("Error calculating Silent Payment tweaks"))

    @hook
    def transaction_dialog_update(self, dialog, tx):
        """
        Updates the UI in the Transaction Dialog to show SP-specific info.
        """
        if any(is_silent_payment_output(out) for out in tx.outputs()):
            # We can add a custom status label or badge to the dialog here
            dialog.status_label.setText(dialog.status_label.text() + " [Silent Payment]")

    @hook
    def format_output(self, output):
        """
        Ensures the History and Tx Dialog show the correct address/label.
        """
        if is_silent_payment_output(output):
            return {
                'address': getattr(output, 'sp_address', _("Silent Payment")),
                'type': 'sp',
                'label': _("Privacy-Enhanced Output")
            }

def requires_settings(self):
        return True

    def settings_dialog(self, window):
        d = WindowModalDialog(window, _("Silent Payments Settings"))
        layout = QVBoxLayout(d)

        layout.addWidget(QLabel(_("Select Indexing Server:")))
        
        # Prefill the dropdown
        self.server_combo = QComboBox()
        servers = [
            "electrs.cakewallet.com:50001",
            "sp.bitaroo.net:50001",
            "localhost:50001 (Local Indexer)"
        ]
        self.server_combo.addItems(servers)
        
        # Set current selection from config
        current_server = self.config.get('sp_index_server', servers[0])
        index = self.server_combo.findText(current_server)
        if index >= 0:
            self.server_combo.setCurrentIndex(index)
            
        layout.addWidget(self.server_combo)
        layout.addStretch()

        layout.addLayout(Buttons(Buttons.CANCEL, Buttons.OK))
        if d.exec():
            new_server = self.server_combo.currentText()
            self.config.set_key('sp_index_server', new_server)
            # Notify the scanner to reconnect
            if hasattr(self, 'scanner'):
                self.scanner.reconnect(new_server)