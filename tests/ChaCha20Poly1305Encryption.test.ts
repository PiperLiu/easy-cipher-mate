import { ChaCha20Poly1305Encryption, ChaCha20Poly1305EncryptionConfigFromEnv } from '../src/encryption/ChaCha20Poly1305Encryption';
import { deriveStringToBuffer } from '../src/utils/stringCoding';

describe('ChaCha20Poly1305Encryption', () => {
    const password = 'test-password';
    const salt = deriveStringToBuffer('test-salt', 16);
    const nonce = deriveStringToBuffer('test-nonce', ChaCha20Poly1305Encryption.NONCE_LENGTH);

    const encryption = new ChaCha20Poly1305Encryption();

    describe('encryptText and decryptText', () => {
        it('should encrypt and decrypt text correctly', async () => {
            const plaintext = 'Hello, World!';
            const config = { password, salt, nonce };

            const encrypted = await encryption.encryptText(plaintext, config);

            const decrypted = await encryption.decryptText(encrypted.data, config);

            expect(decrypted).toBe(plaintext);
        });

        it('should encrypt and decrypt text with different encodings', async () => {
            const plaintext = 'Hello, World! Special chars: ñáéíóú';
            const encodings = ['utf-8', 'utf16le', 'base64', 'hex', 'latin1', 'binary'] as const;

            for (const encoding of encodings) {
                const config = { password, salt, nonce, textEncoding: encoding };

                const encrypted = await encryption.encryptText(plaintext, config);
                const decrypted = await encryption.decryptText(encrypted.data, config);

                expect(decrypted).toBe(plaintext);
            }
        });

        it('should handle empty strings', async () => {
            const plaintext = '';
            const config = { password, salt, nonce };

            const encrypted = await encryption.encryptText(plaintext, config);
            const decrypted = await encryption.decryptText(encrypted.data, config);

            expect(decrypted).toBe(plaintext);
        });
    });

    describe('encryptFile and decryptFile', () => {
        it('should encrypt and decrypt file data correctly', async () => {
            const fileDataBuffer = Buffer.from('This is file content');
            const fileData = fileDataBuffer.buffer.slice(fileDataBuffer.byteOffset, fileDataBuffer.byteOffset + fileDataBuffer.byteLength);
            const config = { password, salt, nonce };

            const encrypted = await encryption.encryptFile(fileData, config);
            const decrypted = await encryption.decryptFile(encrypted.data, config);

            expect(Buffer.from(decrypted)).toEqual(Buffer.from(fileData));
        });

        it('should handle empty file data', async () => {
            const fileData = Buffer.from('').buffer;
            const config = { password, salt, nonce };

            const encrypted = await encryption.encryptFile(fileData, config);
            const decrypted = await encryption.decryptFile(encrypted.data, config);

            expect(Buffer.from(decrypted)).toEqual(Buffer.from(fileData));
        });
    });

    describe('ChaCha20Poly1305EncryptionConfigFromEnv', () => {
        const originalEnv = process.env;

        beforeEach(() => {
            jest.resetModules();
            process.env = { ...originalEnv };
        });

        afterAll(() => {
            process.env = originalEnv;
        });

        it('should use provided values', () => {
            const config = new ChaCha20Poly1305EncryptionConfigFromEnv(
                'test-password',
                salt,
                nonce,
                'base64'
            );

            expect(config.password).toBe('test-password');
            expect(config.salt).toEqual(salt);
            expect(config.nonce).toEqual(nonce);
            expect(config.textEncoding).toBe('base64');
        });

        it('should use environment variables', () => {
            process.env.ECM_CHACHA20_PASSWORD = 'env-password';
            process.env.ECM_CHACHA20_SALT = 'env-salt-value';
            process.env.ECM_CHACHA20_NONCE = 'env-nonce-val12'; // 12 characters for proper nonce length
            process.env.ECM_TEXT_ENCODING = 'hex';

            const config = new ChaCha20Poly1305EncryptionConfigFromEnv();

            expect(config.password).toBe('env-password');
            expect(config.salt).toBeDefined();
            expect(config.nonce).toBeDefined();
            expect(config.textEncoding).toBe('hex');
        });
    });

    describe('Error handling', () => {
        it('should throw error with invalid nonce length', () => {
            const invalidNonce = deriveStringToBuffer('short', 5);
            const config = { password, salt, nonce: invalidNonce };

            expect(() => {
                encryption.validateNonce(invalidNonce);
            }).toThrow('Nonce must be 12 bytes');

            expect(async () => {
                await encryption.encryptText('test', config);
            }).rejects.toThrow();
        });
    });
});
