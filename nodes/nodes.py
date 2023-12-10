from flask import Flask, jsonify, render_template, request
from argparse import ArgumentParser
from time import time
from flask_cors import CORS
from Crypto.PublicKey import RSA
import binascii
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5 as pk
from Crypto.Hash import SHA
from uuid import uuid4
import json
import hashlib
import requests
from urllib.parse import urlparse
MINING_SENDER = "BLOCKCHAIN"
MINNING_REWARD=1
MINNING_DIFFICULTY = 2

class Blockchain:
    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()
        self.node_id = str(uuid4()).replace('-', '')
        self.create_block(0,'00')

    def create_block(self, nonce=None, previous_hash=None):
        """
        Add block of transaction in blockchain        
        Keyword arguments:
        argument -- description
        Return: return_description
        """
        
        block = {
            'block_number':len(self.chain)+1,
            'timestamp':time(),
            'transactions':self.transactions,
            'nonce':nonce,
            'previous_hash':previous_hash
        }
        
        #reset current list
        self.transactions = []
        self.chain.append(block)

        return block

    def verify_tansaction_signature(self, sender_public_key, signature, transaction):
        public_key = RSA.import_key(binascii.unhexlify(sender_public_key))
        verifier = pk.new(public_key)
        val = SHA.new(str(transaction).encode('utf8'))

        try:
            verifier.verify(val, binascii.unhexlify(signature))
            return True
        
        except ValueError:
            return False

    def submit_transaction(self, sender_public_key, recipient_public_key, signature, amount):
        """
        TODO:REWARD THE MINER
        TODO: SIGNATURE VALIDATION
        
        Return: chain length or False id sign is not verified
        """

        transaction = OrderedDict({
            'sender_public_key': sender_public_key,
            'recipient_public_key': recipient_public_key,
            'amount':amount
        })

        if sender_public_key == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain)+1
        else:
            signature_verification = self.verify_tansaction_signature(sender_public_key, signature, transaction)
            if signature_verification:
                self.transactions.append(transaction)
                return len(self.chain)+1
            else:
                return False
            
    @staticmethod
    def valid_proof(transactions, last_hash, nonce, difficulty=MINNING_DIFFICULTY):
        guess = (str(transactions)+str(last_hash)+str(nonce)).encode('utf8')
        hash = hashlib.new('sha256')
        hash.update(guess)

        guess_hash = hash.hexdigest()
        
        return guess_hash[:difficulty] == '0'*difficulty

    def proof_of_work(self):
        nonce = 0
        last_hash = self.hash(blockchain.chain[-1])
        while not self.valid_proof(self.transactions, last_hash, nonce):
            nonce+=1
        
        return nonce
    
    @staticmethod
    def hash(block):
        #to ensure dictionary is ordered use sort_keys in dumps
        block_str = json.dumps(block, sort_keys=True).encode('utf8')
        hash = hashlib.new('sha256')
        hash.update(block_str)
        return hash.hexdigest()
    
    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get('http://'+node+'/chain')
            if response.status_code==200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length>max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain
        
        if new_chain:
            self.chain = new_chain
            return True
        
        return False

    def valid_chain(self, chain):
        last_block = chain[0]
        cur_idx = 1

        while cur_idx<len(chain):
            block = chain[cur_idx]
            transactions = block['transactions'][:-1]
            transactions_elements = ['sender_public_key', 'recipient_public_key', 'amount']

            transactions = [OrderedDict((k, transaction[k]) for k in transactions_elements) for transaction in transactions]

            if block['previous_hash']!=self.hash(last_block) or not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINNING_DIFFICULTY):
                return False
            
            last_block = block
            cur_idx+=1
        
        return True
    
    def register_node(self, node_url):
        parsed_url = urlparse(node_url)
        print(parsed_url,'!!!!!!!!!!!!!!!!!!!!!!!')
        if parsed_url.netloc:
            self.nodes.add(node_url)
        
        elif parsed_url.path:
            self.nodes.add(node_url)
        
        else:
            raise ValueError('Invalid URL.')
    
#Initialise blockchain
blockchain = Blockchain()

#initialise node
app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/transactions/new', methods=['POST'])
def new_transactions():
    values = request.form
    required = ['confirmation_sender_public_key', 'confirmation_recipient_public_key', 'transaction_signature', 'confirmation_amount']

    if not all(k in values for k in required):
        return 'Missing values', 400
    
    amount = values["confirmation_amount"]
    sender_public_key = values["confirmation_sender_public_key"]
    signature = values["transaction_signature"]
    recipient_public_key = values["confirmation_recipient_public_key"]

    result = blockchain.submit_transaction(sender_public_key, recipient_public_key, signature, amount)
    if not result:
        response = {
            'message':'Invalid Transaction'
            }
        return jsonify(response), 406
    
    else:
        response = {
            'message':'Transaction will be added to the block '+str(result)
            }
        return jsonify(response), 201

@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    transactions = blockchain.transactions
    response = {'transactions': transactions}

    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }

    return jsonify(response), 200

@app.route('/mine', methods=['GET'])
def mine():
    nonce = blockchain.proof_of_work()

    blockchain.submit_transaction(sender_public_key=MINING_SENDER,
                                  recipient_public_key=blockchain.node_id,
                                  signature='', 
                                  amount=MINNING_REWARD
                                )
    last_block = blockchain.chain[-1]
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)
    response = {
        'message':'New Block Created.',
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce':block['nonce'],
        'previous_hash':block['previous_hash']
    }

    return jsonify(response), 200

@app.route('/configure')
def configure():
    return render_template('configure.html')

@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes':nodes}
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    print(values)
    # 127.0.0.1:5052, 127.0.0.1:5053, 127.0.0.1:5054
    nodes = values.get('nodes').replace(' ', '').split(',')
    print(nodes,'##########################')
    if not nodes[0]:
        return 'Error: Please supply valid node list', 400
    
    for node_url in nodes:
        blockchain.register_node(node_url)

    print(blockchain.nodes,'??????????????????????????/')
    response = {
        'message': 'Nodes have been added',
        'total_nodes': [node for node in blockchain.nodes]
    }

    return jsonify(response), 200

if __name__=="__main__":
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5001, type=int, help="port to listen to")

    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)