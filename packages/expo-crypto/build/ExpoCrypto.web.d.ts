import { TypedArray } from 'expo-modules-core';
import { CryptoDigestAlgorithm, CryptoDigestOptions, CryptoHmacAlgorithm, CryptoHmacOptions } from './Crypto.types';
declare const _default: {
    digestStringAsync(algorithm: CryptoDigestAlgorithm, data: string, options: CryptoDigestOptions): Promise<string>;
    getRandomBytes(length: number): Uint8Array;
    getRandomBytesAsync(length: number): Promise<Uint8Array>;
    getRandomValues(typedArray: TypedArray): TypedArray;
    randomUUID(): `${string}-${string}-${string}-${string}-${string}`;
    digestAsync(algorithm: AlgorithmIdentifier, data: ArrayBuffer): Promise<ArrayBuffer>;
    hmacAsync(algorithm: CryptoHmacAlgorithm, key: BufferSource, data: BufferSource): Promise<ArrayBuffer>;
    hmac(algorithm: CryptoHmacAlgorithm, output: TypedArray, key: BufferSource, data: BufferSource): void;
    hmacStringAsync(algorithm: CryptoHmacAlgorithm, key: string, data: string, options: CryptoHmacOptions): Promise<string>;
};
export default _default;
//# sourceMappingURL=ExpoCrypto.web.d.ts.map