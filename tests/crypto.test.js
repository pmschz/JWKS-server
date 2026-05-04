import { decryptText, encryptText } from '../src/crypto.js';

describe('crypto helpers', () => {
  test('encryptText and decryptText round-trip', () => {
    const plaintext = JSON.stringify({ hello: 'world' });
    const encrypted = encryptText(plaintext, 'secret-key');
    const decrypted = decryptText(encrypted, 'secret-key');
    expect(decrypted).toBe(plaintext);
  });

  test('encryptText throws for missing secret', () => {
    expect(() => encryptText('abc', '')).toThrow('NOT_MY_KEY must be set for AES encryption');
  });

  test('decryptText throws for malformed payload', () => {
    expect(() => decryptText('bad-payload', 'secret-key')).toThrow('Encrypted payload format is invalid');
  });
});
