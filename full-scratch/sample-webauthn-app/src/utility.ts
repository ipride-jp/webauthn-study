export const urlsafeBase64TextToUint8Array = (text: string) => {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const paddedBase64 = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    "="
  );

  const binaryString = atob(paddedBase64);

  const uint8Array = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    uint8Array[i] = binaryString.charCodeAt(i);
  }

  const arrayBuffer = uint8Array.buffer;

  return arrayBuffer;
};

export const uint8ArrayToUrlsafeBase64Text = (arrayBuffer: ArrayBuffer) => {
  const uint8Array = new Uint8Array(arrayBuffer);

  let binaryString = "";
  for (let i = 0; i < uint8Array.length; i++) {
    binaryString += String.fromCharCode(uint8Array[i]);
  }

  const base64 = btoa(binaryString);

  const text = base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

  return text;
};
