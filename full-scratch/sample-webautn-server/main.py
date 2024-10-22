import base64
import hashlib
import json
import secrets
import sqlite3

import cbor2
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn


CLIENT_URL = 'http://localhost:3000'
SERVER_PORT = 8080
RP_ID = 'localhost'


class RegisterRequest(BaseModel):
  name: str
  displayName: str


class CredentialResponseResponse(BaseModel):
  attestationObject: str
  clientDataJSON: str


class RegisterResponse(BaseModel):
  attestationObject: str
  clientDataJSON: str
  id: str
  credentialId: str


class LoginRequest(BaseModel):
  name: str


class LoginResponse(BaseModel):
  authenticatorData: str
  clientDataJSON: str
  name: str
  credentialId: str
  signature: str


def init_db():
  with sqlite3.connect('users.db') as conn:
    cursor = conn.cursor()
    # cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('''
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        displayName TEXT NOT NULL,
        challenge TEXT NOT NULL,
        publicKey TEXT
      )
    ''')
    conn.commit()


def url_safe_base64_text_to_binary(text: str) -> bytes:
  missing_padding = len(text) % 4
  if missing_padding:
    text += '=' * (4 - missing_padding)

  decoded_bytes = base64.urlsafe_b64decode(text)
  return decoded_bytes


def url_safe_base64_text_to_string(text: str) -> str:
    return url_safe_base64_text_to_binary(text).decode('utf-8')


app = FastAPI()
# noinspection PyTypeChecker
app.add_middleware(
  CORSMiddleware,
  allow_origins=[CLIENT_URL],
  allow_credentials=True,
  allow_methods=['*'],
  allow_headers=['*'],
)
init_db()


@app.post('/api/register/response')
def register_response(payload: RegisterResponse):
  with sqlite3.connect('users.db') as conn:
    cursor = conn.cursor()

    # Fetch the challenge from the database
    cursor.execute('SELECT challenge FROM users WHERE id = ?', (payload.id,))
    stored_challenge = cursor.fetchone()

    if not stored_challenge:
      raise HTTPException(status_code=400, detail='User not found')

    stored_challenge = stored_challenge[0]

  # Verify the challenge matches
  client_data_json = json.loads(url_safe_base64_text_to_string(payload.clientDataJSON))
  if stored_challenge != client_data_json['challenge']:
    raise HTTPException(status_code=400, detail='Invalid challenge')

  # Verify the origin URL
  if client_data_json['origin'] != CLIENT_URL:
    raise HTTPException(status_code=400, detail='Invalid origin')

  # Verify the attestation
  attestation_object = cbor2.loads(url_safe_base64_text_to_binary(payload.attestationObject))
  from pprint import pprint
  pprint(attestation_object)
  if attestation_object['fmt'] != 'none':
    raise HTTPException(status_code=400, detail='Unsupported attestation')
  auth_data = attestation_object['authData']
  id_length = int.from_bytes(auth_data[53:55], byteorder='big')
  public_key_cbor = auth_data[55 + id_length:]
  credential_public_key = cbor2.loads(public_key_cbor)
  pprint(credential_public_key)

  with sqlite3.connect('users.db') as conn:
    cursor = conn.cursor()
    cursor.execute('''
     UPDATE users
     SET publicKey = ?
     WHERE id = ?
    ''', (json.dumps({
      'id': payload.credentialId,
      'rawId': payload.credentialId,
      'response': {
        'attestationObject': payload.attestationObject,
        'clientDataJSON': payload.clientDataJSON
      },
      'publicKey': base64.b64encode(public_key_cbor).decode('ascii') if attestation_object['fmt'] == 'none' else ''
    }), payload.id))
    conn.commit()
  return {'status': 'ok'}


@app.post('/api/register')
def register_account(register_request: RegisterRequest):
  user_id = secrets.token_urlsafe(32)
  challenge = secrets.token_urlsafe(32)

  with sqlite3.connect('users.db') as conn:
    cursor = conn.cursor()
    cursor.execute('''
      INSERT INTO users (id, name, displayName, challenge)
      VALUES (?, ?, ?, ?)
    ''', (user_id, register_request.name, register_request.displayName, challenge))
    conn.commit()

  return {
    'challenge': challenge,
    'rp': {
      'id': RP_ID,
      'name': 'Sample WebAuthn Server.'
    },
    'user': {
      'id': user_id,
      'name': register_request.name,
      'displayName': register_request.displayName
    },
    'pubKeyCredParams': [
      {
        'type': 'public-key',
        'alg': -7
      },
      {
        'type': 'public-key',
        'alg': -257
      }
    ],
    'timeout': 60000,
    'attestation': 'none'
  }


@app.post('/api/login/response')
def log_response(payload: LoginResponse):
  with sqlite3.connect('users.db') as conn:
    cursor = conn.cursor()

    # Fetch the challenge from the database
    cursor.execute('SELECT challenge FROM users WHERE name = ?', (payload.name,))
    stored_challenge = cursor.fetchone()

    if not stored_challenge:
      raise HTTPException(status_code=400, detail='User not found')

    stored_challenge = stored_challenge[0]

  # Verify the challenge matches
  client_data_json = json.loads(url_safe_base64_text_to_string(payload.clientDataJSON))
  if stored_challenge != client_data_json['challenge']:
    raise HTTPException(status_code=400, detail='Invalid challenge')

  # Verify the origin URL
  if client_data_json['origin'] != CLIENT_URL:
    raise HTTPException(status_code=400, detail='Invalid origin')

  # Verify the authenticatorData
  authenticator_data = url_safe_base64_text_to_binary(payload.authenticatorData)

  rp_id_hash = authenticator_data[0:32]
  hash_sha256 = hashlib.sha256(RP_ID.encode())
  if hash_sha256.digest() != rp_id_hash:
    raise HTTPException(status_code=400, detail='Invalid RP ID')

  flags = authenticator_data[32]
  if flags & 0b00000001 == 0:
    raise HTTPException(status_code=400, detail='User not present')
  if flags & 0b00000100 == 0:
    raise HTTPException(status_code=400, detail='User not verified')

  return {'status': 'ok'}


@app.post('/api/login')
def login(login_request: LoginRequest):
  challenge = secrets.token_urlsafe(32)

  with sqlite3.connect('users.db') as conn:
    cursor = conn.cursor()

    # Fetch the challenge from the database
    cursor.execute('SELECT publicKey FROM users WHERE name = ?', (login_request.name,))
    stored_public_key = cursor.fetchone()

    if not stored_public_key:
      raise HTTPException(status_code=400, detail='User not found')

    stored_public_key = stored_public_key[0]

  stored_public_key_json = json.loads(stored_public_key)

  with sqlite3.connect('users.db') as conn:
    cursor = conn.cursor()
    cursor.execute('''
     UPDATE users
     SET challenge = ?
     WHERE name = ?
    ''', (challenge, login_request.name))
    conn.commit()

  return {
    'challenge': challenge,
    'allowCredentials': [
      {
        'transports': ['internal'],
        'type': 'public-key',
        'id': stored_public_key_json['id'],
      }
    ],
  }


if __name__ == '__main__':
  uvicorn.run(app, host='0.0.0.0', port=SERVER_PORT)
