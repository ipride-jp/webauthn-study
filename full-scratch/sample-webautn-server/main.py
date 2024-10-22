import base64
import hashlib
import json
import secrets
import sqlite3

import cbor2
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

CLIENT_URL = 'http://localhost:3000'
SERVER_PORT = 8080
RP_ID = 'localhost'
RP_NAME = 'Sample WebAuthn Server.'


class RegisterRequest(BaseModel):
  name: str
  displayName: str


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
  with sqlite3.connect('webauthn.db') as conn:
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS register_challenge (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        displayName TEXT NOT NULL,
        challenge TEXT NOT NULL
      )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS login_challenge (
      name TEXT NOT NULL,
      challenge TEXT NOT NULL
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        credential_id TEXT NOT NULL,
        credential_public_key BLOB NOT NULL,
        sign_count INTEGER NOT NULL,
        name TEXT NOT NULL,
        displayName TEXT NOT NULL
    )''')
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


@app.post('/api/register')
def register_account_endpoint(register_request: RegisterRequest):
  user_id = secrets.token_urlsafe(32)
  challenge = secrets.token_urlsafe(32)

  with sqlite3.connect('webauthn.db') as conn:
    cursor = conn.cursor()
    cursor.execute('DELETE FROM register_challenge WHERE name = ?', (register_request.name,))
    cursor.execute('''
      INSERT OR IGNORE INTO register_challenge (id, name, displayName, challenge)
      VALUES (?, ?, ?, ?)
    ''', (
      user_id,
      register_request.name,
      register_request.displayName,
      challenge,
    ))
    cursor.execute('''
      UPDATE register_challenge SET id = ?, displayName = ?, challenge = ? WHERE name = ?
    ''', (
      user_id,
      register_request.displayName,
      challenge,
      register_request.name,
    ))

  return {
    'challenge': challenge,
    'rp': {
      'id': RP_ID,
      'name': RP_NAME
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


@app.post('/api/register/response')
def register_response_endpoint(register_response: RegisterResponse):
  with sqlite3.connect('webauthn.db') as conn:
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, displayName, challenge FROM register_challenge WHERE id = ?',
                   (register_response.id,))
    row = cursor.fetchone()
    if row is None:
      return Response(
        content=json.dumps({'status': 'error', 'message': 'Invalid ID.'}),
        media_type='application/json',
        status_code=400
      )
    (user_id, user_name, user_display_name, user_challenge) = row
  print((user_id, user_name, user_display_name, user_challenge))

  # Verify the challenge matches
  client_data_json = json.loads(url_safe_base64_text_to_string(register_response.clientDataJSON))
  if user_challenge != client_data_json['challenge']:
    raise HTTPException(status_code=400, detail='Invalid challenge')

  # Verify the origin URL
  if client_data_json['origin'] != CLIENT_URL:
    raise HTTPException(status_code=400, detail='Invalid origin')

  # Verify the attestation
  attestation_object = cbor2.loads(url_safe_base64_text_to_binary(register_response.attestationObject))
  if attestation_object['fmt'] != 'none':
    raise HTTPException(status_code=400, detail='Unsupported attestation')
  auth_data = attestation_object['authData']
  sign_count = int.from_bytes(auth_data[33:37], byteorder='big')
  id_length = int.from_bytes(auth_data[53:55], byteorder='big')
  public_key_cbor = auth_data[55 + id_length:]

  with sqlite3.connect('webauthn.db') as conn:
    cursor = conn.cursor()
    cursor.execute('DELETE FROM register_challenge WHERE id = ?', (user_id,))
    cursor.execute('''
      INSERT OR IGNORE INTO users (id, credential_id, credential_public_key, sign_count, name, displayName)
      VALUES (?, ?, ?, ?, ?, ?)
    ''', (
      user_id,
      register_response.credentialId,
      public_key_cbor,
      sign_count,
      user_name,
      user_display_name,
    ))
    cursor.execute('''
      UPDATE users SET credential_id = ?, credential_public_key = ?, sign_count = ?, name = ?, displayName = ?
      WHERE id = ?
    ''', (
      register_response.credentialId,
      public_key_cbor,
      sign_count,
      user_name,
      user_display_name,
      user_id,
    ))
    conn.commit()

  return {'status': 'ok'}


@app.post('/api/login')
def login_account_endpoint(login_request: LoginRequest):
  challenge = secrets.token_urlsafe(32)

  with sqlite3.connect('webauthn.db') as conn:
    cursor = conn.cursor()
    cursor.execute('SELECT name FROM users WHERE name = ?',
                   (login_request.name,))
    row = cursor.fetchone()
    if row is None:
      return Response(
        content=json.dumps({'status': 'error', 'message': 'User not found.'}),
        media_type='application/json',
        status_code=400
      )

  with sqlite3.connect('webauthn.db') as conn:
    cursor = conn.cursor()
    cursor.execute('''
      INSERT OR IGNORE INTO login_challenge (name, challenge)
      VALUES (?, ?)
    ''', (
      login_request.name,
      challenge,
    ))
    cursor.execute('''
      UPDATE login_challenge SET challenge = ? WHERE name = ?
    ''', (
      challenge,
      login_request.name,
    ))

  with sqlite3.connect('webauthn.db') as conn:
    cursor = conn.cursor()
    cursor.execute('SELECT credential_id FROM users WHERE name = ?', (login_request.name,))
    row = cursor.fetchone()
    if row is None:
      return Response(
        content=json.dumps({'status': 'error', 'message': 'User not found.'}),
        media_type='application/json',
        status_code=400
      )
    credential_id = row[0]

  return {
    'challenge': challenge,
    'allowCredentials': [
      {
        'transports': ['internal'],
        'type': 'public-key',
        'id': credential_id,
      }
    ],
  }


@app.post('/api/login/response')
def login_response_endpoint(login_response: LoginResponse):
  with sqlite3.connect('webauthn.db') as conn:
    cursor = conn.cursor()
    cursor.execute('SELECT name, challenge FROM login_challenge WHERE name = ?',
                   (login_response.name,))
    row = cursor.fetchone()
    if row is None:
      return Response(
        content=json.dumps({'status': 'error', 'message': 'Invalid name.'}),
        media_type='application/json',
        status_code=400
      )
    cursor.execute('DELETE FROM login_challenge WHERE name = ?', (login_response.name,))
    (user_name, user_challenge) = row

  # Verify the challenge matches
  client_data_json = json.loads(url_safe_base64_text_to_string(login_response.clientDataJSON))
  if user_challenge != client_data_json['challenge']:
    raise HTTPException(status_code=400, detail='Invalid challenge')

  # Verify the origin URL
  if client_data_json['origin'] != CLIENT_URL:
    raise HTTPException(status_code=400, detail='Invalid origin')

  # Verify the authenticatorData
  authenticator_data = url_safe_base64_text_to_binary(login_response.authenticatorData)

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


if __name__ == '__main__':
  uvicorn.run(app, host='0.0.0.0', port=SERVER_PORT)
