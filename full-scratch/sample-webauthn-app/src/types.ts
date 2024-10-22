export type RegisterResponseJson = {
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
};

export type LoginResponseJson = {
  challenge: string;
  allowCredentials: {
    type: string;
    id: string;
    transports: string[];
  }[];
};
