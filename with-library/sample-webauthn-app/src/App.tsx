import { useState } from "react";
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/types';

export const authConfig = {
  serverUri: 'http://localhost:8080',
}

const App = () =>  {

  const [name, setName] = useState('user2');
  const [displayName, setDisplayName] = useState('User2');
  const [statusMessageList, setStatusMessageList] = useState<{
    message: string,
    type: 'success' | 'danger',
  }[]>([]);

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
      const registerResponseJson = (await registerResponse.json()) as PublicKeyCredentialCreationOptionsJSON;
      const credential = await startRegistration(registerResponseJson);

      const registerResponseResponse = await fetch(`${authConfig.serverUri}/api/register/response`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          id: registerResponseJson.user.id,
          credentialId: credential.id,
          attestationObject: credential.response.attestationObject,
          clientDataJSON: credential.response.clientDataJSON,
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
    } catch (e) {
      console.error(e);
      setStatusMessageList([...statusMessageList, {
        message: 'Failed to register.',
        type: 'danger',
      }]);
    }
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
    const loginResponseJson = (await loginResponse.json()) as PublicKeyCredentialRequestOptionsJSON;
    const credential = await startAuthentication(loginResponseJson);
    
    const loginResponseResponse = await fetch(`${authConfig.serverUri}/api/login/response`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name,
        credentialId: credential.id,
        authenticatorData: credential.response.authenticatorData,
        clientDataJSON: credential.response.clientDataJSON,
        signature: credential.response.signature,
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
