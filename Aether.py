import hashlib
import time

# Nome e iniciais da Criptomoeda
CRYPTOCURRENCY_NAME = "Aether AI"  # Nome da criptomoeda
CRYPTOCURRENCY_INITIALS = "AAI"     # Iniciais da criptomoeda

class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash

    def __str__(self):
        return f"Block #{self.index} [Previous Hash: {self.previous_hash}, Timestamp: {self.timestamp}, Data: {self.data}, Hash: {self.hash}]"

def calculate_hash(index, previous_hash, timestamp, data):
    value = f"{index}{previous_hash}{timestamp}{data}"
    return hashlib.sha256(value.encode()).hexdigest()

def create_genesis_block():
    return Block(0, "0", int(time.time()), f"{CRYPTOCURRENCY_NAME} Genesis Block", calculate_hash(0, "0", int(time.time()), f"{CRYPTOCURRENCY_NAME} Genesis Block"))

def create_new_block(previous_block, data):
    index = previous_block.index + 1
    timestamp = int(time.time())
    hash = calculate_hash(index, previous_block.hash, timestamp, data)
    return Block(index, previous_block.hash, timestamp, data, hash)

# Criação da Blockchain
blockchain = [create_genesis_block()]
previous_block = blockchain[0]

# Adicionando novos blocos à blockchain
for i in range(1, 5):  # Adiciona 4 novos blocos
    new_block_data = f"{CRYPTOCURRENCY_INITIALS} - {CRYPTOCURRENCY_NAME} Block {i} Data"
    new_block = create_new_block(previous_block, new_block_data)
    blockchain.append(new_block)
    previous_block = new_block
    print(new_block)


class Transaction:
    def __init__(self, sender, recipient, amount):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount

    def __str__(self):
        return f"Transaction from {self.sender} to {self.recipient} of {self.amount} units"

    def to_dict(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount
        }

class Block:
    def __init__(self, index, previous_hash, transactions, timestamp=None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp or time.time()
        self.transactions = transactions  # Lista de transações
        self.nonce = 0  # Número usado na prova de trabalho
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calcula o hash do bloco com base em seu conteúdo."""
        block_content = (str(self.index) + str(self.previous_hash) + str(self.timestamp) +
                         str([str(tx) for tx in self.transactions]) + str(self.nonce))
        return hashlib.sha256(block_content.encode()).hexdigest()

    def mine_block(self, difficulty):
        """Minerar o bloco ajustando o nonce até encontrar um hash que comece com 'difficulty' zeros."""
        while self.hash[:difficulty] != "0" * difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()

    def __str__(self):
        transactions = "\n".join([str(tx) for tx in self.transactions])
        return f"Block #{self.index}\nHash: {self.hash}\nPrevious Hash: {self.previous_hash}\nTransactions:\n{transactions}\n"

class Blockchain:
    def __init__(self, difficulty=2):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.pending_transactions = []  # Lista de transações pendentes
        self.mining_reward = 10

    def create_genesis_block(self):
        """Cria o bloco inicial (bloco gênesis) da blockchain."""
        return Block(0, "0", [Transaction("System", "FirstUser", 100)])

    def get_latest_block(self):
        return self.chain[-1]

    def create_transaction(self, transaction):
        """Adiciona uma transação à lista de transações pendentes."""
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self, miner_address):
        """Cria um novo bloco com as transações pendentes e recompensa o minerador."""
        new_block = Block(len(self.chain), self.get_latest_block().hash, self.pending_transactions)
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

        # Recompensa o minerador
        self.pending_transactions = [Transaction("System", miner_address, self.mining_reward)]

    def is_chain_valid(self):
        """Verifica se a blockchain é válida, comparando os hashes dos blocos."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    def print_chain(self):
        """Imprime a blockchain completa."""
        for block in self.chain:
            print(block)



#Criação de carteiras: Chaves publicas e privada

import hashlib
import ecdsa
import base58

class Wallet:
    def __init__(self):
        self.private_key = self.generate_private_key()
        self.public_key = self.generate_public_key(self.private_key)
        self.address = self.generate_address(self.public_key)

    def generate_private_key(self):
        """Gera uma chave privada de 256 bits"""
        return ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    def generate_public_key(self, private_key):
        """Gera uma chave pública a partir da chave privada"""
        return private_key.get_verifying_key()

    def generate_address(self, public_key):
        """Gera um endereço usando SHA-256 e RIPEMD-160"""
        public_key_bytes = public_key.to_string()
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        
        # Adiciona o prefixo para o endereço e codifica usando Base58
        prefixed_ripemd160 = b'\x00' + ripemd160_hash
        checksum = hashlib.sha256(hashlib.sha256(prefixed_ripemd160).digest()).digest()[:4]
        full_hash = prefixed_ripemd160 + checksum
        address = base58.b58encode(full_hash).decode('utf-8')
        return address

    def get_address(self):
        return self.address

    def sign_transaction(self, message):
        """Assina uma mensagem com a chave privada"""
        return self.private_key.sign(message.encode())

# Criação de uma nova carteira
my_wallet = Wallet()
print(f"Endereço da carteira: {my_wallet.get_address()}")


# Verifica o saldo da Carteira
#__________________________________________________________________________________________________________________________

class Blockchain:
    # (Parte anterior do código)
    
    def get_balance(self, address):
        """Calcula o saldo de uma carteira com base nas transações da blockchain."""
        balance = 0
        for block in self.chain:
            for tx in block.transactions:
                if tx.sender == address:
                    balance -= tx.amount
                if tx.recipient == address:
                    balance += tx.amount
        return balance

# Criando uma blockchain e uma carteira
blockchain = Blockchain()
my_wallet = Wallet()
recipient_wallet = Wallet()

# Criando uma transação e verificando o saldo
transaction = Transaction(my_wallet.get_address(), recipient_wallet.get_address(), 20)
blockchain.create_transaction(transaction)

# Minerando para processar a transação
blockchain.mine_pending_transactions(my_wallet.get_address())

# Verificando os saldos das carteiras
print(f"Saldo da minha carteira: {blockchain.get_balance(my_wallet.get_address())}")
print(f"Saldo da carteira do destinatário: {blockchain.get_balance(recipient_wallet.get_address())}")






#__________________________________________________________________________________________________________
# Exemplo de Implementação em Python: Rede P2P Simples
#__________________________________________________________________________________________________________


# import socket
# import threading
# import pickle

# class P2PNode:
#     def __init__(self, host, port):
#         self.host = host
#         self.port = port
#         self.peers = []

#     def start_server(self):
#         server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         server_socket.bind((self.host, self.port))
#         server_socket.listen(5)
#         print(f"Node listening on {self.host}:{self.port}...")

#         while True:
#             client_socket, client_address = server_socket.accept()
#             threading.Thread(target=self.handle_client, args=(client_socket,)).start()

#     def handle_client(self, client_socket):
#         try:
#             while True:
#                 data = client_socket.recv(4096)
#                 if not data:
#                     break
#                 message = pickle.loads(data)
#                 print(f"Received message: {message}")
#                 # Lógica de processamento de mensagens
#         except Exception as e:
#             print(f"Error handling client: {e}")
#         finally:
#             client_socket.close()

#     def connect_to_peer(self, peer_host, peer_port):
#         try:
#             peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             peer_socket.connect((peer_host, peer_port))
#             self.peers.append(peer_socket)
#             print(f"Connected to peer {peer_host}:{peer_port}")
#         except Exception as e:
#             print(f"Error connecting to peer: {e}")

#     def send_message_to_peers(self, message):
#         data = pickle.dumps(message)
#         for peer_socket in self.peers:
#             peer_socket.sendall(data)

# # Criar um nó e iniciar o servidor
# node = P2PNode('192.168.15.184', 8000)
# threading.Thread(target=node.start_server).start()

# Conectar-se a outro nó (se necessário)
# node.connect_to_peer('outro_no_host', 8001)

# Enviar uma mensagem para os peers
# node.send_message_to_peers("Nova transação na rede")
