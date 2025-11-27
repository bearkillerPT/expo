import { CodedError, TypedArray } from 'expo-modules-core';

import { CryptoDigestAlgorithm, CryptoEncoding, CryptoDigestOptions, CryptoHmacAlgorithm } from './Crypto.types';

const getCrypto = (): Crypto => window.crypto ?? (window as any).msCrypto;

export default {
  async digestStringAsync(
    algorithm: CryptoDigestAlgorithm,
    data: string,
    options: CryptoDigestOptions
  ): Promise<string> {
    if (!crypto.subtle) {
      throw new CodedError(
        'ERR_CRYPTO_UNAVAILABLE',
        'Access to the WebCrypto API is restricted to secure origins (localhost/https).'
      );
    }
    const encoder = new TextEncoder();
    const buffer = encoder.encode(data);
    const hashedData = await crypto.subtle.digest(algorithm, buffer);
    if (options.encoding === CryptoEncoding.HEX) {
      return hexString(hashedData);
    } else if (options.encoding === CryptoEncoding.BASE64) {
      return btoa(String.fromCharCode(...new Uint8Array(hashedData)));
    }
    throw new CodedError('ERR_CRYPTO_DIGEST', 'Invalid encoding type provided.');
  },
  getRandomBytes(length: number): Uint8Array {
    const array = new Uint8Array(length);
    return getCrypto().getRandomValues(array);
  },
  async getRandomBytesAsync(length: number): Promise<Uint8Array> {
    const array = new Uint8Array(length);
    return getCrypto().getRandomValues(array);
  },
  getRandomValues(typedArray: TypedArray) {
    return getCrypto().getRandomValues(typedArray);
  },
  randomUUID() {
    return getCrypto().randomUUID();
  },
  digestAsync(algorithm: AlgorithmIdentifier, data: ArrayBuffer): Promise<ArrayBuffer> {
    return getCrypto().subtle.digest(algorithm, data);
  },
  async hmacAsync(
    algorithm: CryptoHmacAlgorithm,
    key: BufferSource,
    data: BufferSource
  ): Promise<ArrayBuffer> {
    if (!crypto.subtle) {
      throw new CodedError(
        'ERR_CRYPTO_UNAVAILABLE',
        'Access to the WebCrypto API is restricted to secure origins (localhost/https).'
      );
    }
    const hashName = algorithm.split('HMAC-')[1]; // e.g. SHA-256
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(key),
      { name: 'HMAC', hash: { name: hashName } },
      false,
      ['sign']
    );
    const mac = await crypto.subtle.sign('HMAC', cryptoKey, toArrayBuffer(data));
    return mac;
  },
};

function hexString(buffer: ArrayBuffer): string {
  const byteArray = new Uint8Array(buffer);

  const hexCodes = [...byteArray].map((value) => {
    const hexCode = value.toString(16);
    const paddedHexCode = hexCode.padStart(2, '0');
    return paddedHexCode;
  });

  return hexCodes.join('');
}

function toArrayBuffer(data: BufferSource): ArrayBuffer {
  if (data instanceof ArrayBuffer) return data;
  if (ArrayBuffer.isView(data)) {
    return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  }
  // Fallback: try to handle Uint8Array-like
  const u8 = new Uint8Array(data as any);
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}
