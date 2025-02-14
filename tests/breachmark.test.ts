import { AESGCMEncryption, AESGCMEncryptionConfigFromEnv } from '../src/encryption/AESGCMEncryption';
import { ChaCha20Poly1305Encryption, ChaCha20Poly1305EncryptionConfigFromEnv } from '../src/encryption/ChaCha20Poly1305Encryption';
import { EncryptionService } from '../src/services/EncryptionService';

// 假设密码、文本和加密服务已经在环境中配置好
const password = "test-password";
const plaintext = "This is a long string for benchmarking encryption performance.".repeat(100); // 长文本
const testFileContent = "This is a test file for benchmarking encryption performance.".repeat(100);

describe('Encryption Algorithm Performance Benchmark', () => {
    let encryptionServiceAES: EncryptionService<AESGCMEncryption, AESGCMEncryptionConfigFromEnv>;
    let encryptionServiceChaCha: EncryptionService<ChaCha20Poly1305Encryption, ChaCha20Poly1305EncryptionConfigFromEnv>;

    beforeAll(() => {
        const aesEncryption = new AESGCMEncryption();
        const aesEncryptionConfig = new AESGCMEncryptionConfigFromEnv(password);
        encryptionServiceAES = new EncryptionService(aesEncryption, aesEncryptionConfig);

        const chaChaEncryption = new ChaCha20Poly1305Encryption();
        const chaChaEncryptionConfig = new ChaCha20Poly1305EncryptionConfigFromEnv(password);
        encryptionServiceChaCha = new EncryptionService(chaChaEncryption, chaChaEncryptionConfig);
    });

    it('should benchmark AES-GCM encryption and decryption speed', async () => {
        console.time('AES-GCM Encryption Time');
        await encryptionServiceAES.encryptText(plaintext);
        console.timeEnd('AES-GCM Encryption Time');

        console.time('AES-GCM Decryption Time');
        const encryptedData = await encryptionServiceAES.encryptText(plaintext);
        await encryptionServiceAES.decryptText(encryptedData.data);
        console.timeEnd('AES-GCM Decryption Time');
    });

    it('should benchmark ChaCha20-Poly1305 encryption and decryption speed', async () => {
        console.time('ChaCha20-Poly1305 Encryption Time');
        await encryptionServiceChaCha.encryptText(plaintext);
        console.timeEnd('ChaCha20-Poly1305 Encryption Time');

        console.time('ChaCha20-Poly1305 Decryption Time');
        const encryptedData = await encryptionServiceChaCha.encryptText(plaintext);
        await encryptionServiceChaCha.decryptText(encryptedData.data);
        console.timeEnd('ChaCha20-Poly1305 Decryption Time');
    });

    it('should benchmark AES-GCM file encryption and decryption speed', async () => {
        const fileBuffer = Buffer.from(testFileContent);

        console.time('AES-GCM File Encryption Time');
        await encryptionServiceAES.encryptFile(fileBuffer.buffer);
        console.timeEnd('AES-GCM File Encryption Time');

        console.time('AES-GCM File Decryption Time');
        const encryptionResult = await encryptionServiceAES.encryptFile(fileBuffer.buffer);
        await encryptionServiceAES.decryptFile(encryptionResult.data);
        console.timeEnd('AES-GCM File Decryption Time');
    });

    it('should benchmark ChaCha20-Poly1305 file encryption and decryption speed', async () => {
        const fileBuffer = Buffer.from(testFileContent);

        console.time('ChaCha20-Poly1305 File Encryption Time');
        await encryptionServiceChaCha.encryptFile(fileBuffer.buffer);
        console.timeEnd('ChaCha20-Poly1305 File Encryption Time');

        console.time('ChaCha20-Poly1305 File Decryption Time');
        const encryptionResult = await encryptionServiceChaCha.encryptFile(fileBuffer.buffer);
        await encryptionServiceChaCha.decryptFile(encryptionResult.data);
        console.timeEnd('ChaCha20-Poly1305 File Decryption Time');
    });
});
