from flask import Flask, request, jsonify
from base64 import b64encode, b64decode
import jwt
import os
from tinydb import TinyDB, Query
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import logging
import logging.config
import subprocess
import json
import urllib.request

log_level = {
  'CRITICAL': 50,
  'ERROR': 40,
  'WARN': 30,
  'INFO': 20,
  'DEBUG': 10
}

logger = logging.getLogger('app')
AWS_Key = "AKIAILE3JG6KMS3HZGCA"
Secret_Key = "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"
app = Flask(__name__)
os.system("echo '{\"_default\": {}}' > mydb.json")
my_db = TinyDB('mydb.json')
table = my_db.table('user_password')
#jwtpass = 'myr@nd0mp@ssw0rd'
enc_key = "abcdefghijklmnop".encode('utf-8')


@app.before_first_request
def before_first_request():
    # db.truncate()
    print("All data cleaned")


def get_cipher():
    return AES.new(enc_key, AES.MODE_ECB)



def encrypt_value(value):
    cipher = get_cipher()
    cipher_val = cipher.encrypt(pad(value.encode('utf-8'), 16))
    base = b64encode(cipher_val).decode()
    return base

def decrypt_value(value):
    value = b64decode(value.encode('utf-8'))
    cipher = get_cipher()
    plain_text = unpad(cipher.decrypt(value), 16)
    return plain_text.decode()

def command(cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()
        return out

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
