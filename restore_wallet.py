from mnemonic import Mnemonic
from bip32utils import BIP32Key

mnemonic = "your mnemonic phrase here"
seed = Mnemonic("english").to_seed(mnemonic)
bip32_root_key = BIP32Key.fromEntropy(seed)
derived_key = bip32_root_key.ChildKey(0).ChildKey(0)
address = derived_key.Address()
private_key = derived_key.WalletImportFormat()
print(f"Restored Address: {address}, Private Key: {private_key}")