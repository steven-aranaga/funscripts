import os
import sys
import time
import csv
import json
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dataclasses import dataclass
from functools import lru_cache
import signal
import logging
import logging.handlers
from contextlib import contextmanager
from threading import Lock
from enum import Enum

from dotenv import load_dotenv
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from mnemonic import Mnemonic
from bip32utils import BIP32Key
from tenacity import retry, stop_after_attempt, wait_exponential
from cryptography.fernet import Fernet

# Load environment variables
load_dotenv()

# Configuration using dataclass
@dataclass
class WalletConfig:
    rpc_host: str = "127.0.0.1"
    rpc_port: str = "8332"
    wallet_name: str = "watch-wallet"
    min_active_wallets: int = 50
    check_interval: int = 300  # 5 minutes
    balance_threshold: float = 1.0  # BTC
    max_show_balance: float = 30.0  # BTC 
    max_sale_balance: float = 15.0  # BTC
    dormancy_days: int = 365  # Days without activity
    wallet_paths: Dict[str, Path] = None
    encryption_key: Optional[bytes] = None

    def __post_init__(self):
        if self.wallet_paths is None:
            self.wallet_paths = {
                "wallets": Path("wallets.csv"),
                "active": Path("active_wallets.txt"),
                "private_keys": Path("private_keys.txt")
            }
        if not self.encryption_key:
            self.encryption_key = Fernet.generate_key()


# Key constants for wallet fields
WALLET_FIELDS = ["address", "private_key", "mnemonic", "status", "imported"]

class WalletStatus(Enum):
    ACTIVE = "active"
    EXCEEDED = "exceeded"
    RETIRED = "retired"

class State:
    is_shutting_down: bool = False
    current_operation: str = "idle"
    file_lock: Lock = Lock()


# Exceptions for specific error types
class WalletError(Exception):
    pass

class ConfigurationError(Exception):
    pass

class RPCError(Exception):
    pass


# Logging setup with enhanced configurability
def setup_logging(name: str, log_file: str = None) -> logging.Logger:
    """Configure logging with rotation and proper formatting."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s'
    )
    
    # File handler with rotation
    if not log_file:
        log_file = f"{name}.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10_000_000, backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False
    
    return logger


@contextmanager
def file_lock_context():
    """Context manager for thread-safe file operations."""
    try:
        State.file_lock.acquire()
        yield
    finally:
        State.file_lock.release()


class WalletManager:
    def __init__(self, config: WalletConfig):
        self.config = config
        self.logger = setup_logging("wallet_manager")
        self.fernet = Fernet(config.encryption_key)
        self.rpc_connection = None
        self.last_summary_time = time.time()
        self.summary_stats = {key: 0 for key in ["wallets_checked", "new_wallets", "exceeded_wallets", "retired_wallets"]}
        
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    def connect_to_node(self) -> AuthServiceProxy:
        """Connect to the Bitcoin node."""
        rpc_url = (
            f"http://{os.getenv('RPC_USER')}:{os.getenv('RPC_PASSWORD')}@"
            f"{self.config.rpc_host}:{self.config.rpc_port}/wallet/{self.config.wallet_name}"
        )
        try:
            self.rpc_connection = AuthServiceProxy(rpc_url, timeout=360)
            return self.rpc_connection
        except Exception as e:
            raise RPCError(f"Failed to connect to RPC node: {e}")

    def generate_wallet(self) -> Dict[str, str]:
        """Generate and encrypt a new wallet."""
        try:
            # Generate mnemonic and derive keys
            mnemo = Mnemonic("english")
            mnemonic = mnemo.generate(strength=256)
            seed = mnemo.to_seed(mnemonic)
            bip32_root_key = BIP32Key.fromEntropy(seed)
            derived_key = bip32_root_key.ChildKey(0).ChildKey(0)
            
            private_key = derived_key.WalletImportFormat()
            address = derived_key.Address()
            
            # Encrypt sensitive fields
            encrypted_wallet = {
                "address": address,
                "private_key": self.fernet.encrypt(private_key.encode()).decode(),
                "mnemonic": self.fernet.encrypt(mnemonic.encode()).decode(),
                "status": WalletStatus.ACTIVE.value,
                "imported": "no"
            }
            
            self.logger.info(f"Generated wallet: {address}")
            return encrypted_wallet
        except Exception as e:
            raise WalletError(f"Failed to generate wallet: {e}")

    def load_wallets(self) -> List[Dict[str, str]]:
        """Load wallets from a CSV file with thread safety."""
        with file_lock_context():
            if not self.config.wallet_paths["wallets"].exists():
                return []
            
            try:
                with open(self.config.wallet_paths["wallets"], "r") as file:
                    wallets = list(csv.DictReader(file))
                    return wallets
            except Exception as e:
                raise WalletError(f"Failed to load wallets: {e}")

    def save_wallets(self, wallets: List[Dict[str, str]]) -> None:
        """Save wallets to a CSV file."""
        with file_lock_context():
            try:
                with open(self.config.wallet_paths["wallets"], "w", newline="") as file:
                    writer = csv.DictWriter(file, fieldnames=WALLET_FIELDS)
                    writer.writeheader()
                    writer.writerows(wallets)
            except Exception as e:
                raise WalletError(f"Failed to save wallets: {e}")

    def get_wallet_balance(self, address: str) -> float:
        """Fetch wallet balance with retry."""
        try:
            utxos = self.rpc_connection.listunspent(0, 9999999, [address])
            return sum(utxo["amount"] for utxo in utxos)
        except JSONRPCException as e:
            self.import_address_as_descriptor(address)
            return 0
        except Exception as e:
            raise RPCError(f"Failed to get balance for {address}: {e}")

    def import_address_as_descriptor(self, address: str) -> None:
        """Import wallet address as descriptor."""
        descriptor = f"addr({address})"
        try:
            self.rpc_connection.importdescriptors([{
                "desc": descriptor,
                "timestamp": "now",
                "active": True,
                "internal": False,
                "watchonly": True
            }])
            self.logger.info(f"Imported address {address} as descriptor")
        except Exception as e:
            raise RPCError(f"Failed to import descriptor for {address}: {e}")

    def _secure_erase(self, wallet: Dict[str, str]) -> None:
        """Securely overwrite wallet data in memory."""
        try:
            # Overwrite sensitive data
            wallet["private_key"] = b"\x00" * 32
            wallet["mnemonic"] = b"\x00" * 32
            # Force garbage collection
            import gc
            gc.collect()
        except Exception as e:
            self.logger.error(f"Secure erase failed: {e}")

    def _log_audit_event(self, event_type: str, address: str) -> None:
        """Write to append-only audit log"""
        audit_log = Path("audit.log")
        with file_lock_context():
            with open(audit_log, "a") as f:
                f.write(f"{datetime.utcnow().isoformat()} | {event_type} | {address}\n")

    def update_wallet_files(self, wallets: List[Dict[str, str]]) -> None:
        """Update all wallet-related files atomically."""
        with file_lock_context():
            try:
                # Update active wallets file atomically
                with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_active:
                    for wallet in wallets:
                        if wallet["status"] == WalletStatus.ACTIVE.value:
                            temp_active.write(f"{wallet['address']}\n")
                    os.replace(temp_active.name, self.config.wallet_paths["active"])

                # Update private keys file
                with open(self.config.wallet_paths["private_keys"], "w") as f:
                    for wallet in wallets:
                        if (wallet["status"] == WalletStatus.EXCEEDED.value and 
                            self.get_wallet_balance(wallet["address"]) > 0):
                            # Decrypt private key before writing
                            decrypted_key = self.fernet.decrypt(
                                wallet["private_key"].encode()
                            ).decode()
                            f.write(f"{decrypted_key}\n")
                            
            except Exception as e:
                raise WalletError(f"Failed to update wallet files: {e}")

    def log_summary(self, force: bool = False) -> None:
        """Log summary statistics if enough time has passed or forced."""
        current_time = time.time()
        if force or (current_time - self.last_summary_time) >= 3600:  # Log every hour
            self.logger.info(
                f"Summary: Checked {self.summary_stats['wallets_checked']} wallets, "
                f"Generated {self.summary_stats['new_wallets']} new, "
                f"Found {self.summary_stats['exceeded_wallets']} exceeded, "
                f"Retired {self.summary_stats['retired_wallets']}"
            )
            self.last_summary_time = current_time
            self.summary_stats = {key: 0 for key in self.summary_stats}

    def monitor_wallets(self) -> None:
        """Main wallet monitoring loop with improved logging."""
        try:
            self.rpc_connection = self.connect_to_node()
            self.logger.info("Starting wallet monitoring...")
            
            while not State.is_shutting_down:
                try:
                    wallets = self.load_wallets()
                    active_wallets = [w for w in wallets if w["status"] == WalletStatus.ACTIVE.value]
                    self.logger.info(f"Monitoring {len(active_wallets)} active wallets")
                    
                    # Monitor existing wallets
                    for wallet in active_wallets:
                        if State.is_shutting_down:
                            break
                            
                        self.summary_stats["wallets_checked"] += 1
                        address = wallet["address"]
                        
                        if wallet["imported"] == "no":
                            self.import_address_as_descriptor(address)
                            wallet["imported"] = "yes"
                            
                        balance = self.get_wallet_balance(address)
                        
                        if balance > self.config.balance_threshold:
                            self.logger.info(f"Retiring wallet {address} with balance {balance} BTC")
                            wallet["status"] = WalletStatus.EXCEEDED.value
                            self.summary_stats["exceeded_wallets"] += 1
                        elif balance == 0 and wallet["status"] == WalletStatus.EXCEEDED.value:
                            self.logger.debug(f"Marking wallet {address} as retired")
                            wallet["status"] = WalletStatus.RETIRED.value
                            self.summary_stats["retired_wallets"] += 1
                    
                    # Generate new wallets if needed
                    active_count = len([w for w in wallets if w["status"] == WalletStatus.ACTIVE.value])
                    new_wallets_needed = self.config.min_active_wallets - active_count
                    if new_wallets_needed > 0:
                        self.logger.info(f"Generating {new_wallets_needed} new wallets")
                        
                    while active_count < self.config.min_active_wallets:
                        if State.is_shutting_down:
                            break
                        wallets.append(self.generate_wallet())
                        self.summary_stats["new_wallets"] += 1
                        active_count += 1
                    
                    # Save updates and log summary
                    self.save_wallets(wallets)
                    self.update_wallet_files(wallets)
                    self.log_summary()
                    
                    if not State.is_shutting_down:
                        time.sleep(self.config.check_interval)
                        
                except Exception as e:
                    self.logger.error(f"Error in monitoring loop: {e}")
                    time.sleep(60)  # Wait before retrying
                    
        except Exception as e:
            self.logger.error(f"Fatal error in wallet monitoring: {e}")
            raise
        finally:
            self.log_summary(force=True)  # Log final summary before shutdown

def signal_handler(signum, frame):
    """Handle shutdown signals."""
    State.is_shutting_down = True

def main():
    # Validate environment variables
    if not all([os.getenv('RPC_USER'), os.getenv('RPC_PASSWORD')]):
        raise ConfigurationError("Missing required environment variables")
    
    # Initialize configuration
    config = WalletConfig()
    
    # Set up signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Initialize and run wallet manager
    wallet_manager = WalletManager(config)
    
    try:
        # Initialize wallets if needed
        if not config.wallet_paths["wallets"].exists():
            wallets = [wallet_manager.generate_wallet() for _ in range(config.min_active_wallets)]
            wallet_manager.save_wallets(wallets)
        
        # Start monitoring
        wallet_manager.monitor_wallets()
        
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
