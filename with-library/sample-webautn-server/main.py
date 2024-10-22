import json
import sqlite3

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from webauthn import (
  generate_authentication_options,
  generate_registration_options,
  options_to_json,
  verify_authentication_response,
  verify_registration_response,
  base64url_to_bytes
)

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
        id BLOB PRIMARY KEY,
        name TEXT NOT NULL,
        displayName TEXT NOT NULL,
        challenge BLOB NOT NULL
      )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS login_challenge (
      name TEXT NOT NULL,
      challenge BLOB NOT NULL
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id BLOB PRIMARY KEY,
        credential_id BLOB NOT NULL,
        credential_public_key BLOB NOT NULL,
        sign_count INTEGER NOT NULL,
        name TEXT NOT NULL,
        displayName TEXT NOT NULL
    )''')
    conn.commit()


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
  simple_registration_options = generate_registration_options(
    rp_id=RP_ID,
    rp_name=RP_NAME,
    user_name=register_request.name,
    user_display_name=register_request.displayName,
  )

  with sqlite3.connect('webauthn.db') as conn:
    cursor = conn.cursor()
    cursor.execute('''
      INSERT OR IGNORE INTO register_challenge (id, name, displayName, challenge)
      VALUES (?, ?, ?, ?)
    ''', (
      simple_registration_options.user.id,
      register_request.name,
      register_request.displayName,
      simple_registration_options.challenge,
    ))
    cursor.execute('''
      UPDATE register_challenge SET id = ?, displayName = ?, challenge = ? WHERE name = ?
    ''', (
      simple_registration_options.user.id,
      register_request.displayName,
      simple_registration_options.challenge,
      register_request.name,
    ))

  res = Response(
    content=options_to_json(simple_registration_options),
    media_type='application/json',
    status_code=200
  )
  return res


@app.post('/api/register/response')
def register_response_endpoint(register_response: RegisterResponse):
  with sqlite3.connect('webauthn.db') as conn:
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, displayName, challenge FROM register_challenge WHERE id = ?',
                   (base64url_to_bytes(register_response.id),))
    row = cursor.fetchone()
    if row is None:
      return Response(
        content=json.dumps({'status': 'error', 'message': 'Invalid ID.'}),
        media_type='application/json',
        status_code=400
      )
    (user_id, user_name, user_display_name, user_challenge) = row
  print((user_id, user_name, user_display_name, user_challenge))

  registration_verification = verify_registration_response(
    credential={
      'id': register_response.credentialId,
      'rawId': register_response.credentialId,
      'response': {
        'attestationObject': register_response.attestationObject,
        'clientDataJSON': register_response.clientDataJSON,
      },
      'type': 'public-key',
    },
    expected_challenge=user_challenge,
    expected_origin=CLIENT_URL,
    expected_rp_id=RP_ID,
  )
  if not registration_verification.user_verified:
    return Response(
      content=json.dumps({'status': 'error', 'message': 'User not verified.'}),
      media_type='application/json',
      status_code=400
    )

  with sqlite3.connect('webauthn.db') as conn:
    cursor = conn.cursor()
    cursor.execute('DELETE FROM register_challenge WHERE id = ?', (user_id,))
    cursor.execute('''
      INSERT OR IGNORE INTO users (id, credential_id, credential_public_key, sign_count, name, displayName)
      VALUES (?, ?, ?, ?, ?, ?)
    ''', (
      user_id,
      registration_verification.credential_id,
      registration_verification.credential_public_key,
      registration_verification.sign_count,
      user_name,
      user_display_name,
    ))
    cursor.execute('''
      UPDATE users SET credential_id = ?, credential_public_key = ?, sign_count = ?, name = ?, displayName = ?
      WHERE id = ?
    ''', (
      registration_verification.credential_id,
      registration_verification.credential_public_key,
      registration_verification.sign_count,
      user_name,
      user_display_name,
      user_id,
    ))
    conn.commit()

  return {'status': 'ok'}


@app.post('/api/login')
def login_account_endpoint(login_request: LoginRequest):
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

  simple_authentication_options = generate_authentication_options(
    rp_id=RP_ID,
  )

  with sqlite3.connect('webauthn.db') as conn:
    cursor = conn.cursor()
    cursor.execute('''
      INSERT OR IGNORE INTO login_challenge (name, challenge)
      VALUES (?, ?)
    ''', (
      login_request.name,
      simple_authentication_options.challenge,
    ))
    cursor.execute('''
      UPDATE login_challenge SET challenge = ? WHERE name = ?
    ''', (
      simple_authentication_options.challenge,
      login_request.name,
    ))

  return Response(
    content=options_to_json(simple_authentication_options),
    media_type='application/json',
    status_code=200
  )


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

  with sqlite3.connect('webauthn.db') as conn:
    cursor = conn.cursor()
    cursor.execute('SELECT credential_public_key, sign_count FROM users WHERE name = ?',
                   (login_response.name,))
    row = cursor.fetchone()
    if row is None:
      return Response(
        content=json.dumps({'status': 'error', 'message': 'User not found.'}),
        media_type='application/json',
        status_code=400
      )
    (credential_public_key, sign_count) = row

  try:
    authentication_verification = verify_authentication_response(
      credential={
        'id': login_response.credentialId,
        'rawId': login_response.credentialId,
        'response': {
          'authenticatorData': login_response.authenticatorData,
          'clientDataJSON': login_response.clientDataJSON,
          'signature': login_response.signature,
        },
        'type': 'public-key',
      },
      expected_challenge=user_challenge,
      expected_origin=CLIENT_URL,
      expected_rp_id=RP_ID,
      credential_public_key=credential_public_key,
      credential_current_sign_count=sign_count,
    )

    print(authentication_verification)
    if not authentication_verification.new_sign_count <= sign_count + 1:
      return Response(
        content=json.dumps({'status': 'error', 'message': 'User not verified.'}),
        media_type='application/json',
        status_code=400
      )

    return {'status': 'ok'}
  except Exception as e:
    return Response(
      content=json.dumps({'status': 'error', 'message': str(e)}),
      media_type='application/json',
      status_code=400
    )


if __name__ == '__main__':
  uvicorn.run(app, host='0.0.0.0', port=SERVER_PORT)
