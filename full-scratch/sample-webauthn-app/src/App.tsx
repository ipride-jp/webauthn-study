import { useState } from "react";

export const authConfig = {
  serverUri: 'http://localhost:8080',
}

type RegisterResponseJson = {
  publicKey: {
    challenge: string;
    rp: {
      id: string;
      name: string;
    };
    user: {
      id: string;
      name: string;
      displayName: string;
    };
    pubKeyCredParams: {
      type: string;
      alg: number;
    }[];
    timeout: number;
    attestation: string;
  }
}

type LoginResponseJson = {
  publicKey: {
    challenge: string;
    allowCredentials: {
      type: string;
      id: string;
      transports: string[];
    }[];
  }
}

const urlsafeBase64TextToUint8Array = (text: string) => {
  const base64 = text.replace(/-/g, '+').replace(/_/g, '/');
  const paddedBase64 = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');

  const binaryString = atob(paddedBase64);

  const uint8Array = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    uint8Array[i] = binaryString.charCodeAt(i);
  }

  const arrayBuffer = uint8Array.buffer;

  return arrayBuffer;
}

const uint8ArrayToUrlsafeBase64Text = (arrayBuffer: ArrayBuffer) => {
  const uint8Array = new Uint8Array(arrayBuffer);

  let binaryString = '';
  for (let i = 0; i < uint8Array.length; i++) {
    binaryString += String.fromCharCode(uint8Array[i]);
  }

  const base64 = btoa(binaryString);

  const text = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  return text;
}

const App = () =>  {
  const [name, setName] = useState('user2');
  const [displayName, setDisplayName] = useState('User2');
  const [statusMessageList, setStatusMessageList] = useState<{
    message: string,
    type: 'success' | 'danger',
  }[]>([]);

  const register = async () => {
    const registerResponse = await fetch(`${authConfig.serverUri}/api/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name,
        displayName,
      }),
    });
    if (!registerResponse.ok) {
      setStatusMessageList([...statusMessageList, {
        message: 'Failed to register.',
        type: 'danger',
      }]);
      return;
    }

    const registerResponseJson: RegisterResponseJson = await registerResponse.json();
    const credential = (await navigator.credentials.create({
      publicKey: {
        challenge: urlsafeBase64TextToUint8Array(registerResponseJson.publicKey.challenge),
        rp: {
          id: registerResponseJson.publicKey.rp.id,
          name: registerResponseJson.publicKey.rp.name,
        },
        user: {
          id: urlsafeBase64TextToUint8Array(registerResponseJson.publicKey.user.id),
          name: registerResponseJson.publicKey.user.name,
          displayName: registerResponseJson.publicKey.user.displayName,
        },
        pubKeyCredParams: registerResponseJson.publicKey.pubKeyCredParams as PublicKeyCredentialParameters[],
        timeout: registerResponseJson.publicKey.timeout,
      }
    })) as (PublicKeyCredential | null);
    if (!credential) {
      setStatusMessageList([...statusMessageList, {
        message: 'Failed to register.',
        type: 'danger',
      }]);
      return;
    }

    const credentialResponse = credential.response as AuthenticatorAttestationResponse;
    const registerResponseResponse = await fetch(`${authConfig.serverUri}/api/register/response`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        id: registerResponseJson.publicKey.user.id,
        credential: {
          id: credential.id,
          rawId: uint8ArrayToUrlsafeBase64Text(credential.rawId),
          response: {
            attestationObject: uint8ArrayToUrlsafeBase64Text(credentialResponse.attestationObject),
            clientDataJSON: uint8ArrayToUrlsafeBase64Text(credentialResponse.clientDataJSON),
          },
        }
      }),
    });
    if (!registerResponseResponse.ok) {
      setStatusMessageList([...statusMessageList, {
        message: 'Failed to register.',
        type: 'danger',
      }]);
      return;
    }
    setStatusMessageList([...statusMessageList, {
      message: 'Successfully registered.',
      type: 'success',
    }]);
  }

  const login = async () => {
    const loginResponse = await fetch(`${authConfig.serverUri}/api/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name,
      }),
    });
    if (!loginResponse.ok) {
      setStatusMessageList([...statusMessageList, {
        message: 'Failed to login.',
        type: 'danger',
      }]);
      return;
    }

    const loginResponseJson: LoginResponseJson = await loginResponse.json();

    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge: urlsafeBase64TextToUint8Array(loginResponseJson.publicKey.challenge),
        allowCredentials: loginResponseJson.publicKey.allowCredentials.map((allowCredential) => {
          return {
            type: allowCredential.type as 'public-key',
            id: urlsafeBase64TextToUint8Array(allowCredential.id),
            transports: allowCredential.transports as AuthenticatorTransport[],
          };}
        ),
      },
    })) as (PublicKeyCredential | null);
    if (!credential) {
      setStatusMessageList([...statusMessageList, {
        message: 'Failed to login.',
        type: 'danger',
      }]);
      return;
    }

    const credentialResponse = credential.response as AuthenticatorAssertionResponse;
    const loginResponseResponse = await fetch(`${authConfig.serverUri}/api/login/response`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name,
        authenticatorData: uint8ArrayToUrlsafeBase64Text(credentialResponse.authenticatorData),
        clientDataJSON: uint8ArrayToUrlsafeBase64Text(credentialResponse.clientDataJSON),
        signature: uint8ArrayToUrlsafeBase64Text(credentialResponse.signature),
      }),
    });

    if (!loginResponseResponse.ok) {
      setStatusMessageList([...statusMessageList, {
        message: 'Failed to login.',
        type: 'danger',
      }]);
      return;
    }
    setStatusMessageList([...statusMessageList, {
      message: 'Successfully logged in.',
      type: 'success',
    }]);
          
  }

  return (
    <div className="container">
      <div className="row justify-content-center my-3">
        <div className="col col-6">
          <h1 className=" text-center">WebAuthn Study</h1>
          {
            statusMessageList.map((statusMessage, index) => (
              <div key={index} className={`alert alert-${statusMessage.type} alert-dismissible fade show`} role="alert">
                {statusMessage.message}
                <button type="button" className="btn-close" data-bs-dismiss="alert" aria-label="Close" onClick={() => {
                  setStatusMessageList(statusMessageList.filter((_, i) => i !== index));
                }}></button>
              </div>
            ))
          }
          <form>
            <div className="mb-3">
              <label htmlFor="name" className="form-label">Name</label>
              <input type="text" className="form-control" id="name" value={name} onChange={(e) => {
                setName(e.target.value);
              }} />
            </div>
            <div className="mb-3">
              <label htmlFor="displayName" className="form-label">Display name</label>
              <input type="text" className="form-control" id="displayName" value={displayName} onChange={(e) => {
                setDisplayName(e.target.value);
              }} />
            </div>
            <button type="button" className="btn btn-primary" onClick={register}>Register</button>
            <button type="button" className="btn btn-primary ms-3" onClick={login}>Login</button>
          </form>
        </div>
      </div>
    </div>
  );
}

export default App;
