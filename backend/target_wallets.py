import os
import requests
import gzip
import random
import time
from typing import List, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path
from itertools import islice
from functools import lru_cache
import signal
import logging
import logging.handlers
from tenacity import retry, stop_after_attempt, wait_exponential
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from contextlib import contextmanager
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration using dataclass
@dataclass
class Config:
    file_url: str = "http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz"
    local_file: Path = Path("blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz")
    target_file: Path = Path("target_wallets.tsv")
    btc_min: int = int(0.0001 * 100_000_000)  # 0.0001 BTC in satoshis
    btc_max: int = int(15 * 100_000_000)      # 15 BTC in satoshis
    max_show_balance: int = int(30 * 100_000_000)  # 30 BTC in satoshis
    dormancy_days: int = 365  # Days without activity
    sample_sizes: List[int] = None
    threshold: int = 500
    chunk_size: int = 1_000_000
    wallet_name: str = "target-wallet"
    max_retries: int = 3
    retry_delay: int = 5  # Delay between retries (seconds)
    max_wallets: int = 2000
    check_interval: int = 3600  # Interval to wait between monitoring cycles

    def __post_init__(self):
        if self.sample_sizes is None:
            self.sample_sizes = [50, 50, 100, 300]

# Global state management
class State:
    is_shutting_down: bool = False
    current_operation: str = "idle"

# Custom Exceptions
class ConfigurationError(Exception):
    pass

class RPCError(Exception):
    pass

class DataProcessingError(Exception):
    pass

@dataclass
class Stats:
    lines_processed: int = 0
    wallets_filtered: int = 0
    wallets_monitored: int = 0
    wallets_updated: int = 0
    last_summary_time: float = time.time()

def log_summary(stats: Stats, force: bool = False, *, logger: logging.Logger) -> None:
    """Log summary statistics if enough time has passed or forced."""
    current_time = time.time()
    if force or (current_time - stats.last_summary_time) >= 3600:  # Log every hour
        logger.info(
            f"Summary: Processed {stats.lines_processed:,} lines, "
            f"Filtered {stats.wallets_filtered:,} wallets, "
            f"Monitored {stats.wallets_monitored:,} wallets, "
            f"Updated {stats.wallets_updated:,} wallets"
        )
        stats.last_summary_time = current_time
        # Reset counters except for `lines_processed` which is cumulative
        stats.wallets_filtered = 0
        stats.wallets_monitored = 0
        stats.wallets_updated = 0

def setup_logging() -> logging.Logger:
    """Configure logging with rotation and proper formatting."""
    logger = logging.getLogger("target_wallets")
    logger.setLevel(logging.DEBUG)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s'
    )
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        'target_wallets.log',
        maxBytes=10_000_000,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def validate_environment() -> Tuple[str, str]:
    """Validate and return required environment variables."""
    rpc_user = os.getenv('RPC_USER')
    rpc_password = os.getenv('RPC_PASSWORD')
    
    if not rpc_user or not rpc_password:
        raise ConfigurationError("Missing required environment variables: RPC_USER and/or RPC_PASSWORD")
    
    return rpc_user, rpc_password

@contextmanager
def operation_context(operation_name: str, logger: logging.Logger):
    """Context manager for tracking operations and ensuring cleanup."""
    State.current_operation = operation_name
    logger.debug(f"Starting operation: {operation_name}")
    try:
        yield
    finally:
        State.current_operation = "idle"
        logger.debug(f"Completed operation: {operation_name}")

@lru_cache(maxsize=1)
def get_rpc_connection(wallet_name: str, rpc_user: str, rpc_password: str) -> AuthServiceProxy:
    """Create and cache RPC connection."""
    rpc_url = f"http://{rpc_user}:{rpc_password}@127.0.0.1:8332/wallet/{wallet_name}"
    try:
        return AuthServiceProxy(rpc_url, timeout=120)
    except Exception as e:
        raise RPCError(f"Failed to connect to RPC node: {e}") from e

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10)  # Retry quickly for faster recovery
)
def ensure_wallet_loaded(rpc_connection: AuthServiceProxy, wallet_name: str):
    """Ensure wallet is loaded with retry mechanism."""
    try:
        loaded_wallets = rpc_connection.listwallets()
        if wallet_name not in loaded_wallets:
            rpc_connection.loadwallet(wallet_name)
            logger.info(f"Wallet '{wallet_name}' loaded.")
    except Exception as e:
        raise RPCError(f"Failed to load wallet: {e}") from e

def download_file(config: Config, logger: logging.Logger) -> None:
    """Download file with proper error handling and progress tracking."""
    with operation_context("file_download", logger):
        try:
            response = requests.get(config.file_url, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            block_size = 8192
            downloaded = 0
            
            with open(config.local_file, 'wb') as file:
                for chunk in response.iter_content(block_size):
                    if State.is_shutting_down:
                        raise InterruptedError("Shutdown requested during download.")
                    downloaded += len(chunk)
                    file.write(chunk)
                    
                    if total_size:
                        percent = (downloaded / total_size) * 100
                        logger.debug(f"Download progress: {percent:.2f}%")
        except requests.RequestException as e:
            raise DataProcessingError(f"Failed to download file: {e}") from e

def process_wallet_data(config: Config, logger: logging.Logger, stats: Stats) -> List[Tuple[str, int]]:
    """Process wallet data, filtering and sampling wallets."""
    selected_wallets: List[List[Tuple[str, int]]] = [[] for _ in range(len(config.sample_sizes))]
    
    with operation_context("data_processing", logger):
        try:
            with gzip.open(config.local_file, 'rt') as file:
                # Skip header
                header = next(file)
                logger.debug(f"Processing file header: {header.strip()}")
                
                for line in file:
                    if State.is_shutting_down:
                        logger.info("Shutting down during data processing.")
                        return [wallet for sublist in selected_wallets for wallet in sublist]
                    
                    try:
                        line = line.strip()
                        address, balance = line.split('\t')
                        balance_satoshis = int(balance)
                        
                        # Filter wallets based on balance
                        if config.btc_min <= balance_satoshis <= config.btc_max and balance_satoshis % 10_000 != 0:
                            filtered_wallet = (address, balance_satoshis)
                            stats.wallets_filtered += 1
                            
                            # Randomly sample into sampling buckets
                            for i, sample_size in enumerate(config.sample_sizes):
                                if len(selected_wallets[i]) < sample_size:
                                    selected_wallets[i].append(filtered_wallet)
                                else:
                                    if random.random() < (sample_size / (stats.wallets_filtered + 1)):
                                        replacement_index = random.randint(0, sample_size - 1)
                                        selected_wallets[i][replacement_index] = filtered_wallet
                        
                        stats.lines_processed += 1
                        # Log progress periodically
                        if stats.lines_processed % config.chunk_size == 0:
                            logger.debug(
                                f"Progress: {stats.lines_processed} lines processed, "
                                f"{stats.wallets_filtered} wallets filtered."
                            )
                    except ValueError as e:
                        logger.warning(f"Skipping malformed line: {line} ({e})")
                        continue
            
            logger.info(f"Processed {stats.lines_processed:,} lines from file.")
            log_summary(stats, logger=logger)
            return [wallet for sublist in selected_wallets for wallet in sublist]
        
        except Exception as e:
            raise DataProcessingError(f"Error while processing wallet data: {e}") from e


def monitor_wallets(
    wallet_list: List[Tuple[str, int]],
    config: Config,
    rpc_connection: AuthServiceProxy,
    logger: logging.Logger,
    stats: Stats
) -> List[Tuple[str, int]]:
    """Monitor wallets and update balances while checking filters."""
    updated_wallets = []
    
    with operation_context("wallet_monitoring", logger):
        logger.info(f"Starting monitoring on {len(wallet_list)} wallets.")
        
        for address, original_balance in wallet_list:
            if State.is_shutting_down:
                logger.info("Shutting down during wallet monitoring.")
                break
            
            try:
                stats.wallets_monitored += 1
                balance = get_wallet_balance(rpc_connection, address, config)
                
                if balance is None:
                    continue
                
                if config.btc_min <= balance <= config.btc_max and balance % 10_000 != 0:
                    updated_wallets.append((address, balance))
                    stats.wallets_updated += 1
                else:
                    remove_address_from_descriptor(rpc_connection, address, logger)
                    logger.debug(f"Address {address} removed from monitoring due to out-of-range balance.")
                
                # Add rate limiting to avoid overloading the RPC server
                time.sleep(0.1)
                
                # Log periodically
                log_summary(stats, False, logger=logger)
            except Exception as e:
                logger.error(f"Error monitoring wallet {address}: {e}")
        
        logger.info(f"Completed wallet monitoring with {len(updated_wallets)} wallets updated.")
        return updated_wallets

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10)
)
def get_wallet_balance(rpc_connection: AuthServiceProxy, address: str, config: Config) -> Optional[int]:
    """Retrieve wallet balance via RPC."""
    try:
        result = rpc_connection.scantxoutset("start", [f"addr({address})"])
        if result and 'total_amount' in result:
            # Convert balance from BTC to satoshis
            balance = int(float(result['total_amount']) * 100_000_000)
            return balance
        
        return None
    except JSONRPCException as e:
        logger.exception(f"RPC error while getting balance for {address}: {e}")
        return None
    except Exception as e:
        logger.exception(f"Error while getting wallet balance for {address}: {e}")
        return None

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10)
)
def remove_address_from_descriptor(rpc_connection: AuthServiceProxy, address: str, logger: logging.Logger) -> bool:
    """Remove an address from the wallet descriptor."""
    try:
        desc = rpc_connection.getaddressinfo(address).get('desc')
        if desc:
            rpc_connection.removedescriptor(desc)
            logger.debug(f"Removed descriptor for address: {address}")
            return True
        
        logger.warning(f"No descriptor found for address: {address}")
        return False
    except JSONRPCException as e:
        logger.exception(f"RPC error removing descriptor for {address}: {e}")
        return False
    except Exception as e:
        logger.exception(f"Error removing descriptor for {address}: {e}")
        return False

def cleanup(config: Config, logger: logging.Logger):
    """Perform cleanup tasks."""
    logger.info("Initiating cleanup process.")
    try:
        # Remove local file if it exists
        if config.local_file.exists():
            config.local_file.unlink()
            logger.debug(f"Deleted temporary file: {config.local_file}")
        
        # Additional cleanup logic can be added here
    except Exception as e:
        logger.exception(f"Error during cleanup: {e}")

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global logger  # Ensure logging is available
    if logger:
        logger.info(f"Received signal {signum}. Initiating graceful shutdown.")
    State.is_shutting_down = True

def main():
    """Main entry point to execute the monitoring process."""
    global logger
    config = Config()
    logger = setup_logging()
    stats = Stats()
    
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Validate environment variables
        rpc_user, rpc_password = validate_environment()
        
        # Create RPC connection
        rpc_connection = get_rpc_connection(config.wallet_name, rpc_user, rpc_password)
        ensure_wallet_loaded(rpc_connection, config.wallet_name)
        
        logger.info("Application started. Monitoring wallets.")
        
        # Main processing loop
        while not State.is_shutting_down:
            try:
                wallets = []
                
                # If the target file doesn't exist or is empty, process fresh wallets
                if not config.target_file.exists() or os.path.getsize(config.target_file) == 0:
                    download_file(config, logger)
                    wallets = process_wallet_data(config, logger, stats)
                else:
                    with open(config.target_file, 'r') as file:
                        next(file)  # Skip header
                        wallets = [
                            tuple(line.strip().split('\t'))
                            for line in file
                        ]
                        logger.info(f"Loaded {len(wallets)} wallets from target file.")
                
                # Monitor wallet balances and update as needed
                updated_wallets = monitor_wallets(wallets, config, rpc_connection, logger, stats)
                
                # Write updated wallets to target file
                with open(config.target_file, 'w') as file:
                    file.write("address\tbalance\n")
                    for address, balance in updated_wallets[:config.max_wallets]:
                        file.write(f"{address}\t{balance}\n")
                
                logger.info(f"Updated target file with {len(updated_wallets)} wallets.")
                
                # Sleep before starting the next check interval
                if not State.is_shutting_down:
                    time.sleep(config.check_interval)
            except Exception as e:
                logger.exception(f"Unexpected error in the main loop: {e}")
                time.sleep(60)  # Pause before retrying main loop
    except Exception as e:
        logger.exception(f"Fatal error occurred, shutting down: {e}")
    finally:
        log_summary(stats, force=True, logger=logger)
        cleanup(config, logger)

if __name__ == "__main__":
    main()
