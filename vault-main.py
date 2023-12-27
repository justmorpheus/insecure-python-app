from flask import Flask, request, jsonify
from base64 import b64encode, b64decode
import os
from tinydb import TinyDB, Query
import logging
import hvac  # Import the hvac library to interact with HashiCorp Vault

app = Flask(__name__)

# Initialize the Vault client
client = hvac.Client(
    url=os.environ.get('VAULT_URL', 'http://localhost:8200'),
    token=os.environ.get('VAULT_TOKEN')
)

# Initialize TinyDB
os.system("echo '{\"_default\": {}}' > mydb.json")
my_db = TinyDB('mydb.json')
table = my_db.table('user_password')

# Retrieve encryption key from Vault
VAULT_KEY = os.environ.get('VAULT_KEY', 'my-encryption-key')
jwtpass = client.secrets.kv.v2.read_secret_version(path='creds')['data']['data']['jwtpass']

@app.before_first_request
def before_first_request():
    print("All data cleaned")

def encrypt_value(value):
    value = b64encode(value.encode()).decode()
    ciphertext = client.secrets.transit.encrypt_data(name=VAULT_KEY, plaintext=value)
    return ciphertext['data']['ciphertext']

def decrypt_value(ciphertext):
    plaintext = client.secrets.transit.decrypt_data(name=VAULT_KEY, ciphertext=ciphertext)
    encoded = plaintext['data']['plaintext']
    return b64decode(encoded.encode()).decode()

@app.route('/create-password', methods=['POST'])
def create_password():
    if request.method == 'POST':
        if request.is_json:
            pass_data = request.json
            if 'password' in pass_data:
                encr_passwd = encrypt_value(pass_data['password'])
            else:
                return jsonify({'error': 'Password required'}), 400
            if 'email' in pass_data:
                table.insert({"email": pass_data['email'], "password": encr_passwd})
            else:
                return jsonify({'error': "Email not present"}), 400
            return jsonify({"success": "Password added to the manager"}), 201
          
@app.route('/get-password/<email>')
def get_password(email):
    if request.method == "GET":
        user = Query()
        user_val = table.search(user.email == email)
        if isinstance(user_val, list):
            main_user = user_val[0]
            plain_text = decrypt_value(main_user['password'])
            return jsonify({"email": email, "password": plain_text}), 200



@app.route('/')
def hello():
    return "<body style='background-color:LightGray;'><center><h3 style='background-color:DodgerBlue;'>Hello From Insecure Password Manager</h3></center>"

#SSRF Vulnerability
@app.route('/redirect')
def web():
    try:
        site=request.args.get('url')
        response = urllib.request.urlopen(site)
        output=json.dumps(response.read().decode('utf-8', errors='ignore'))
        return jsonify({"output": output}), 200
    except:
        return ("Error Ocurred")

#Command Execution
@app.route('/date')
def command():
    try:
        cmd = request.args.get('exec')
        count = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        stdout, stderr = count.communicate()
        #print(stdout.decode())
        return jsonify({"output": stdout.decode()}), 200

    except:
        return ("Error Ocurred")
      


if __name__ == "__main__":
    logger.warning('In Main function')
    logging.basicConfig(
      level=log_level['DEBUG'],
      format='%(asctime)s - %(levelname)8s - %(name)9s - %(funcName)15s - %(message)s'
    )
    try:
        app.run(host='0.0.0.0', port=8000)

    except Exception as e:
        logging.error("There was an error starting the server: {}".format(e))

