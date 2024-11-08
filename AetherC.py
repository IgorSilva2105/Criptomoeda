import hashlib
import time
import tkinter as tk
from PIL import Image, ImageTk
import ecdsa
import base58

# Nome e iniciais da Criptomoeda
CRYPTOCURRENCY_NAME = "Aether AI"
CRYPTOCURRENCY_INITIALS = "AAI"

# Classe Block
class Block:
    def __init__(self, index, previous_hash, transactions, timestamp=None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp or time.time()
        self.transactions = transactions
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_content = (str(self.index) + str(self.previous_hash) + str(self.timestamp) +
                         str([str(tx) for tx in self.transactions]) + str(self.nonce))
        return hashlib.sha256(block_content.encode()).hexdigest()

    def mine_block(self, difficulty):
        while self.hash[:difficulty] != "0" * difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()

    def __str__(self):
        transactions = "\n".join([str(tx) for tx in self.transactions])
        return f"Block #{self.index}\nHash: {self.hash}\nPrevious Hash: {self.previous_hash}\nTransactions:\n{transactions}\n"

# Classe Transaction
class Transaction:
    def __init__(self, sender, recipient, amount):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount

    def __str__(self):
        return f"Transaction from {self.sender} to {self.recipient} of {self.amount} units"

# Classe Blockchain
class Blockchain:
    def __init__(self, difficulty=2):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.pending_transactions = []
        self.mining_reward = 10

    def create_genesis_block(self):
        return Block(0, "0", [Transaction("System", "FirstUser", 100)])

    def get_latest_block(self):
        return self.chain[-1]

    def create_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self, miner_address):
        new_block = Block(len(self.chain), self.get_latest_block().hash, self.pending_transactions)
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        self.pending_transactions = [Transaction("System", miner_address, self.mining_reward)]

    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for tx in block.transactions:
                if tx.sender == address:
                    balance -= tx.amount
                if tx.recipient == address:
                    balance += tx.amount
        return balance

    def print_chain(self):
        for block in self.chain:
            print(block)

# Classe Wallet para criar e gerenciar carteiras
class Wallet:
    def __init__(self):
        self.private_key = self.generate_private_key()
        self.public_key = self.generate_public_key(self.private_key)
        self.address = self.generate_address(self.public_key)

    def generate_private_key(self):
        return ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    def generate_public_key(self, private_key):
        return private_key.get_verifying_key()

    def generate_address(self, public_key):
        public_key_bytes = public_key.to_string()
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        prefixed_ripemd160 = b'\x00' + ripemd160_hash
        checksum = hashlib.sha256(hashlib.sha256(prefixed_ripemd160).digest()).digest()[:4]
        full_hash = prefixed_ripemd160 + checksum
        return base58.b58encode(full_hash).decode('utf-8')

    def get_address(self):
        return self.address

# Interface gráfica com Tkinter
class BlockchainApp:
    def __init__(self, root, blockchain):
        self.root = root
        self.blockchain = blockchain
        self.root.title(f"{CRYPTOCURRENCY_NAME} - Blockchain Explorer")
        
        # Carregar e exibir o logo
        self.logo = Image.open("C:/Users/Igor Silva/Downloads/Criptomoeda.png")
        self.logo = self.logo.resize((100, 100), Image.LANCZOS)
        self.logo = ImageTk.PhotoImage(self.logo)
        self.logo_label = tk.Label(root, image=self.logo)
        self.logo_label.pack(pady=10)

        # Exibir o nome da criptomoeda
        self.title_label = tk.Label(root, text=f"{CRYPTOCURRENCY_NAME} ({CRYPTOCURRENCY_INITIALS})", font=("Arial", 20))
        self.title_label.pack()

        # Botão para minerar transações pendentes
        self.mine_button = tk.Button(root, text="Mine Pending Transactions", command=self.mine_transactions)
        self.mine_button.pack(pady=10)

        # Botão para exibir a blockchain
        self.show_chain_button = tk.Button(root, text="Show Blockchain", command=self.show_blockchain)
        self.show_chain_button.pack(pady=10)

        # Área de texto para exibir detalhes da blockchain
        self.chain_text = tk.Text(root, height=15, width=70)
        self.chain_text.pack()

    def mine_transactions(self):
        miner_address = Wallet().get_address()
        self.blockchain.mine_pending_transactions(miner_address)
        self.chain_text.insert(tk.END, f"Block mined! Miner reward sent to {miner_address}\n")

    def show_blockchain(self):
        self.chain_text.delete(1.0, tk.END)  # Limpar o conteúdo
        for block in self.blockchain.chain:
            self.chain_text.insert(tk.END, str(block) + "\n")

# Criar blockchain e interface
blockchain = Blockchain()
root = tk.Tk()
app = BlockchainApp(root, blockchain)
root.mainloop()
