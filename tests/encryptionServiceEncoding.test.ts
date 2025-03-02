import { AESGCMEncryption, AESGCMEncryptionConfigFromJSON } from '../src/encryption/AESGCMEncryption';
import { ChaCha20Poly1305Encryption, ChaCha20Poly1305EncryptionConfigFromEnv } from '../src/encryption/ChaCha20Poly1305Encryption';
import { EncryptionService } from '../src/services/EncryptionService';
import { deriveStringToBuffer, deriveStringToUint8Array } from '../src/utils/stringCoding';
import { TextEncoding } from '../src/utils/encodingUtils';

describe('EncryptionService with different encodings', () => {
  // Test data with various character types
  const testStrings = {
    ascii: 'Hello World 123',
    latin1: 'Hello, World! ñáéíóú',
    chinese: '你好，世界',
    japanese: 'こんにちは世界',
    emoji: '👋 Hello! 🌍',
    mixed: 'English 你好 こんにちは 👋'
  };

  const encodings: TextEncoding[] = ['utf-8', 'ascii', 'utf16le', 'base64', 'hex', 'latin1', 'binary'];

  describe('AESGCMEncryption with different encodings', () => {
    const password = 'test-password';

    encodings.forEach(encoding => {
      it(`should encrypt and decrypt with ${encoding} encoding`, async () => {
        const encryption = new AESGCMEncryption();
        const config = new AESGCMEncryptionConfigFromJSON({
          password,
          salt: 'test-salt',
          iv: 'test-iv',
          textEncoding: encoding
        });

        const service = new EncryptionService(encryption, config);

        // Test with ASCII (should work with all encodings)
        let encrypted = await service.encryptText(testStrings.ascii);
        let decrypted = await service.decryptText(encrypted.data);

        if (encoding === 'ascii') {
          // ASCII can only represent 7-bit ASCII characters
          expect(decrypted).toBe(testStrings.ascii);
        } else {
          expect(decrypted).toBe(testStrings.ascii);
        }

        // Test with Unicode characters for compatible encodings
        if (encoding === 'utf-8' || encoding === 'utf16le' || encoding === 'base64' || encoding === 'hex') {
          encrypted = await service.encryptText(testStrings.mixed);
          decrypted = await service.decryptText(encrypted.data);
          expect(decrypted).toBe(testStrings.mixed);
        }
      });

      it(`should allow override of config encoding with ${encoding}`, async () => {
        const encryption = new AESGCMEncryption();
        // Set a different default encoding in config
        const config = new AESGCMEncryptionConfigFromJSON({
          password,
          salt: 'test-salt',
          iv: 'test-iv',
          textEncoding: 'utf-8'  // Default to utf-8
        });

        const service = new EncryptionService(encryption, config);

        // Override with specific encoding in the method call
        const encrypted = await service.encryptText(testStrings.ascii, encoding);
        const decrypted = await service.decryptText(encrypted.data, encoding);

        expect(decrypted).toBe(testStrings.ascii);
      });
    });
  });

  describe('ChaCha20Poly1305Encryption with different encodings', () => {
    const password = 'test-password';
    const salt = deriveStringToBuffer('test-salt', 16);
    const nonce = deriveStringToBuffer('test-nonce', ChaCha20Poly1305Encryption.NONCE_LENGTH);

    encodings.forEach(encoding => {
      it(`should encrypt and decrypt with ${encoding} encoding`, async () => {
        const encryption = new ChaCha20Poly1305Encryption();
        const config = new ChaCha20Poly1305EncryptionConfigFromEnv(
          password,
          salt,
          nonce,
          encoding
        );

        const service = new EncryptionService(encryption, config);

        // Test with ASCII (should work with all encodings)
        let encrypted = await service.encryptText(testStrings.ascii);
        let decrypted = await service.decryptText(encrypted.data);

        expect(decrypted).toBe(testStrings.ascii);

        // Test with Unicode characters for compatible encodings
        if (encoding === 'utf-8' || encoding === 'utf16le' || encoding === 'base64' || encoding === 'hex') {
          // Test Chinese
          encrypted = await service.encryptText(testStrings.chinese);
          decrypted = await service.decryptText(encrypted.data);
          expect(decrypted).toBe(testStrings.chinese);

          // Test Japanese
          encrypted = await service.encryptText(testStrings.japanese);
          decrypted = await service.decryptText(encrypted.data);
          expect(decrypted).toBe(testStrings.japanese);
        }
      });
    });
  });
});
