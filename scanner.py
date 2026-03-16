import requests
import threading
from electrum.util import ThreadJob
from electrum import ecc

class SilentPaymentScanner(ThreadJob):
    def __init__(self, wallet, signals, config):
        self.wallet = wallet
        self.signals = signals
        self.config = config
        self.running = True
        self.known_sp_outputs = {}
        # Initial server setup
        self.update_server_url()

    def update_server_url(self):
        """Fetches the current server URL from Electrum config."""
        self.server_url = self.config.get('sp_index_server', 'https://electrs.cakewallet.com')

    def reconnect(self):
        """Forces the scanner to refresh its server configuration."""
        self.update_server_url()
        self.known_sp_outputs.clear() # Clear cache on server switch

    def fetch_index(self, height):
        """Polls the dynamic server URL."""
        try:
            url = f"{self.server_url.rstrip('/')}/compute-index/{height}"
            response = requests.get(url, timeout=10)
            return response.json() if response.status_code == 200 else []
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Scanner connection error: {e}")
            return []

    def run(self):
        while self.running:
            # Refresh server URL in case the user changed it in Settings
            self.update_server_url()
            
            # Perform stateless scan
            latest_block = self.wallet.get_local_height()
            tweaks = self.fetch_index(latest_block)
            
            # Process results...
            # (Verification logic remains same)
            
            threading.Event().wait(60)