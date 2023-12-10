from flask import Flask, render_template, jsonify, request
from argparse import ArgumentParser
import Crypto
import Crypto.Random as cr
from Crypto.PublicKey import RSA
import binascii
from collections import OrderedDict
from Crypto.Signature import PKCS1_v1_5 as pk
from Crypto.Hash import SHA

class Transaction:
    def __init__(self, sender_public_key, sender_private_key, recipient_public_key, amount):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount
    
    #generating dict for object response
    def to_dict(self):
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'recipient_public_key': self.recipient_public_key,
            'amount': self.amount
        })

    #generating signature
    def sign_transaction(self):
        private_key = RSA.import_key(binascii.unhexlify(self.sender_private_key))
        signer = pk.new(private_key)
        hash = SHA.new(str(self.to_dict()).encode('utf8'))
        
        return binascii.hexlify(signer.sign(hash)).decode('ascii')

app = Flask(__name__)
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/make/transactions')
def make_transactions():
    return render_template('make_transactions.html')

@app.route('/view/transactions')
def view_transactions():
    return render_template('view_transactions.html')

@app.route('/wallet/new')
def new_wallet():
    random_gen = cr.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()

    response = {
        'private_key': binascii.hexlify(private_key.export_key(format('DER'))).decode('ascii'),
        'public_key': binascii.hexlify(public_key.export_key(format('DER'))).decode('ascii')
    }

    return jsonify(response), 200

@app.route('/generate/transactions', methods=["POST"])
def generate_transactions():
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    recipient_public_key = request.form['recipient_public_key']
    amount = request.form['amount']

    transaction = Transaction(sender_public_key, sender_private_key, recipient_public_key, amount)
    response = {
        'transaction':transaction.to_dict(),
        'signature':transaction.sign_transaction()
    }

    return jsonify(response), 200

if __name__=="__main__":
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8081, type=int, help="port to listen to")

    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)