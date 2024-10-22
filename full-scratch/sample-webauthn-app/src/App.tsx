import { useState } from "react";
import { StatusMessage, StatusMessageView } from "./StatusMessageView";
import { LoginResponseJson, RegisterResponseJson } from "./types";
import { uint8ArrayToUrlsafeBase64Text, urlsafeBase64TextToUint8Array } from "./utility";

export const authConfig = {
  serverUri: 'http://localhost:8080',
}

const App = () =>  {

  const [name, setName] = useState('user2');
  const [displayName, setDisplayName] = useState('User2');
  const [statusMessageList, setStatusMessageList] = useState<StatusMessage[]>([]);

  const register = async () => {
    try {
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
      const registerResponseJson: RegisterResponseJson = await registerResponse.json();
      const credential = (await navigator.credentials.create({
        publicKey: {
          challenge: urlsafeBase64TextToUint8Array(registerResponseJson.challenge),
          rp: {
            id: registerResponseJson.rp.id,
            name: registerResponseJson.rp.name,
          },
          user: {
            id: urlsafeBase64TextToUint8Array(registerResponseJson.user.id),
            name: registerResponseJson.user.name,
            displayName: registerResponseJson.user.displayName,
          },
          pubKeyCredParams: registerResponseJson.pubKeyCredParams as PublicKeyCredentialParameters[],
          timeout: registerResponseJson.timeout,
        }
      })) as (PublicKeyCredential | null);
      if (!credential) {
        throw new Error('Failed to create credential.');
      }
      const credentialResponse = credential.response as AuthenticatorAttestationResponse;

      const registerResponseResponse = await fetch(`${authConfig.serverUri}/api/register/response`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          id: registerResponseJson.user.id,
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
        throw new Error('Failed to register.');
      }

      setStatusMessageList([...statusMessageList, {
        message: 'Successfully registered.',
        type: 'success',
      }]);
    } catch (e) {
      console.error(e);
      setStatusMessageList([...statusMessageList, {
        message: 'Failed to register.',
        type: 'danger',
      }]);
    }
  }

  const login = async () => {
    try {
      const loginResponse = await fetch(`${authConfig.serverUri}/api/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name,
        }),
      });
      const loginResponseJson: LoginResponseJson = await loginResponse.json();
      const credential = (await navigator.credentials.get({
        publicKey: {
          challenge: urlsafeBase64TextToUint8Array(loginResponseJson.challenge),
          allowCredentials: loginResponseJson.allowCredentials.map((allowCredential) => {
            return {
              type: allowCredential.type as 'public-key',
              id: urlsafeBase64TextToUint8Array(allowCredential.id),
              transports: allowCredential.transports as AuthenticatorTransport[],
            };}
          ),
        },
      })) as (PublicKeyCredential | null);
      if (!credential) {
        throw new Error('Failed to get credential.');
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
        throw new Error('Failed to login.');
      }

      setStatusMessageList([...statusMessageList, {
        message: 'Successfully logged in.',
        type: 'success',
      }]);
    } catch (e) {
      console.error(e);
      setStatusMessageList([...statusMessageList, {
        message: 'Failed to login.',
        type: 'danger',
      }]);
    }
  }

  return (
    <div className="container">
      <div className="row justify-content-center my-3">
        <div className="col col-6">
          <h1 className=" text-center">WebAuthn Study</h1>
          <StatusMessageView statusMessageList={statusMessageList} setStatusMessageList={setStatusMessageList} />
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
