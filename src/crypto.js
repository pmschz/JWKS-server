import crypto from 'crypto';

function buildAesKey (secret) {
  if (!secret || typeof secret !== 'string') {
    throw new Error('NOT_MY_KEY must be set for AES encryption');
  }
  return crypto.createHash('sha256').update(secret, 'utf8').digest();
}

export function encryptText (plaintext, secret) {
  const key = buildAesKey(secret);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  return `${iv.toString('base64')}:${encrypted.toString('base64')}:${tag.toString('base64')}`;
}

export function decryptText (encryptedPayload, secret) {
  const key = buildAesKey(secret);
  const [ivB64, cipherB64, tagB64] = encryptedPayload.split(':');
  if (!ivB64 || !cipherB64 || !tagB64) {
    throw new Error('Encrypted payload format is invalid');
  }

  const iv = Buffer.from(ivB64, 'base64');
  const ciphertext = Buffer.from(cipherB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);

  return decrypted.toString('utf8');
}
