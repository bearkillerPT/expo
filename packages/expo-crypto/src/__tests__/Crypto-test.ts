import * as Crypto from '../Crypto';
import ExpoCrypto from '../ExpoCrypto';

jest.mock('../ExpoCrypto', () => ({
  getRandomValues: jest.fn(async () => 0),
  getRandomBase64StringAsync: jest.fn(async () => 0),
  digestStringAsync: jest.fn(async () => 0),
  digestString: jest.fn(async () => 0),
  hmac: jest.fn(() => {}),
  hmacStringAsync: jest.fn(async () => ''),
}));

jest.mock('base64-js', () => ({ toByteArray: jest.fn(() => {}) }));

it(`asserts invalid algorithm errors`, async () => {
  await expect(Crypto.digestStringAsync(null as any, '<DEBUG>')).rejects.toThrow(TypeError);
  await expect(Crypto.digestStringAsync('null' as any, '<DEBUG>')).rejects.toThrow(TypeError);
  await expect(Crypto.digestStringAsync(2 as any, '<DEBUG>')).rejects.toThrow(TypeError);
  await expect(Crypto.digestStringAsync(true as any, '<DEBUG>')).rejects.toThrow(TypeError);
  await expect(Crypto.digestStringAsync(undefined as any, '<DEBUG>')).rejects.toThrow(TypeError);
  await expect(Crypto.digestStringAsync({} as any, '<DEBUG>')).rejects.toThrow(TypeError);
});

it(`asserts invalid data errors`, async () => {
  await expect(
    Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA1, null as any)
  ).rejects.toThrow(TypeError);
  await expect(
    Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA1, 2 as any)
  ).rejects.toThrow(TypeError);
  await expect(
    Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA1, true as any)
  ).rejects.toThrow(TypeError);
  await expect(
    Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA1, undefined as any)
  ).rejects.toThrow(TypeError);
  await expect(
    Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA1, {} as any)
  ).rejects.toThrow(TypeError);
});

it(`asserts invalid encoding errors`, async () => {
  await expect(
    Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA1, '<DEBUG>', {
      encoding: null as any,
    })
  ).rejects.toThrow(TypeError);
  await expect(
    Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA1, '<DEBUG>', { encoding: '' as any })
  ).rejects.toThrow(TypeError);
  await expect(
    Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA1, '<DEBUG>', { encoding: 2 as any })
  ).rejects.toThrow(TypeError);
  await expect(
    Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA1, '<DEBUG>', {
      encoding: true as any,
    })
  ).rejects.toThrow(TypeError);
  await expect(
    Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA1, '<DEBUG>', {
      encoding: undefined as any,
    })
  ).rejects.toThrow(TypeError);
  await expect(
    Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA1, '<DEBUG>', { encoding: {} as any })
  ).rejects.toThrow(TypeError);
});

it(`accepts valid byte counts`, async () => {
  for (const value of [0, 1024, 512.5]) {
    await expect(Crypto.getRandomBytesAsync(value));
    expect(ExpoCrypto.getRandomValues).toHaveBeenCalled();
  }
});

it(`falls back to an alternative native method when getRandomValues is not available`, async () => {
  ExpoCrypto.getRandomValues = null;
  await expect(Crypto.getRandomBytesAsync(1024));
  expect(ExpoCrypto.getRandomBase64StringAsync).toHaveBeenCalled();
});

it(`asserts invalid byte count errors`, async () => {
  await expect(Crypto.getRandomBytesAsync(-1)).rejects.toThrow(TypeError);
  await expect(Crypto.getRandomBytesAsync(1025)).rejects.toThrow(TypeError);
  await expect(Crypto.getRandomBytesAsync('invalid' as any)).rejects.toThrow(TypeError);
  await expect(Crypto.getRandomBytesAsync(null as any)).rejects.toThrow(TypeError);
  await expect(Crypto.getRandomBytesAsync({} as any)).rejects.toThrow(TypeError);
  await expect(Crypto.getRandomBytesAsync(NaN)).rejects.toThrow(TypeError);
});

// HMAC behavior-only tests
const hasHmacStringAsync = !!(ExpoCrypto as any)?.hmacStringAsync;
const hasHmac = typeof (ExpoCrypto as any)?.hmac === 'function';

(hasHmac || hasHmacStringAsync ? it : it.skip)(
  'asserts invalid HMAC algorithm errors',
  async () => {
    if (hasHmac) {
      await expect(
        Crypto.hmac('invalid' as any, new Uint8Array(), new Uint8Array())
      ).rejects.toThrow(TypeError);
    }
    if (hasHmacStringAsync) {
      await expect(
        Crypto.hmacStringAsync('invalid' as any, 'k', 'd', { encoding: Crypto.CryptoEncoding.HEX })
      ).rejects.toThrow(TypeError);
    }
  }
);

(hasHmacStringAsync ? it : it.skip)(
  'asserts invalid HMAC encoding errors for string API',
  async () => {
    await expect(
      // @ts-expect-error invalid encoding
      Crypto.hmacStringAsync(Crypto.CryptoHmacAlgorithm.SHA256, 'k', 'd', { encoding: '' })
    ).rejects.toThrow(TypeError);
  }
);

(hasHmacStringAsync ? it : it.skip)('invokes native hmacStringAsync correctly', async () => {
  const value = await Crypto.hmacStringAsync(Crypto.CryptoHmacAlgorithm.SHA256, 'k', 'd', {
    encoding: Crypto.CryptoEncoding.HEX,
  });
  expect(typeof value).toBe('string');
});

(hasHmac ? it : it.skip)('invokes native hmac correctly', async () => {
  const key = new Uint8Array([1, 2]);
  const data = new Uint8Array([3, 4]);
  const buf = await Crypto.hmac(Crypto.CryptoHmacAlgorithm.SHA1, key, data);
  expect(buf instanceof ArrayBuffer).toBe(true);
});
