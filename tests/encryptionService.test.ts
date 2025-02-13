import { AESGCMEncryption, AESGCMEncryptionConfigFromEnv } from "../src/encryption/AESGCMEncryption";
import { EncryptionService } from "../src/services/EncryptionService";
import { readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';

// Increase the default timeout in case encryption/decryption takes a bit longer
jest.setTimeout(10000);

describe("EncryptionService using AESGCMEncryption", () => {
    const password = "test-password";
    const plaintext = "Hello, Unit Testing!";
    const testFileName = "easy-cipher-mate-encryption-test.txt";
    const testFileContent = "Test file content for encryption.";

    let encryptionService: EncryptionService<AESGCMEncryption, AESGCMEncryptionConfigFromEnv>;

    beforeAll(() => {
        const aesEncryption = new AESGCMEncryption();
        const aesEncryptionConfig = new AESGCMEncryptionConfigFromEnv(password);
        encryptionService = new EncryptionService(aesEncryption, aesEncryptionConfig);
    });

    it("should encrypt and decrypt text correctly", async () => {
        // Encrypt the plaintext
        const encryptionResult = await encryptionService.encryptText(plaintext);
        expect(encryptionResult).toHaveProperty("data");

        // Decrypt the ciphertext
        const decryptedText = await encryptionService.decryptText(encryptionResult.data);

        expect(decryptedText).toBe(plaintext);
    });

    it("should convert between string and array buffer correctly", () => {
        // Test string to array buffer
        const buffer = encryptionService.stringToArrayBuffer(plaintext);
        expect(buffer).toBeInstanceOf(ArrayBuffer);

        // Test array buffer to string
        const convertedString = encryptionService.arrayBufferToString(buffer);
        expect(convertedString).toBe(plaintext);
    });

    it("should handle file encryption and decryption correctly", async () => {
        // Create temporary test file
        const tempDir = tmpdir();
        const testFilePath = `${tempDir}/${testFileName}`;
        writeFileSync(testFilePath, testFileContent);

        try {
            // Encrypt the file
            const encryptionResult = await encryptionService.encryptFileByName(testFilePath);
            expect(encryptionResult).toHaveProperty("data");

            // Decrypt the file
            await encryptionService.decryptFileByName(encryptionResult, testFilePath);

            // Verify decrypted file content
            const decryptedContent = readFileSync(testFilePath).toString();
            expect(decryptedContent).toBe(testFileContent);
        } finally {
            // Clean up test file
            try {
                writeFileSync(testFilePath, '');
                writeFileSync(testFilePath, '');
            } catch (err) {
                console.error('Error cleaning up test file:', err);
            }
        }
    });

    it("should handle file buffer encryption and decryption correctly", async () => {
        // Create file buffer from test content
        const fileBuffer = Buffer.from(testFileContent);
        const arrayBuffer = fileBuffer.buffer.slice(fileBuffer.byteOffset, fileBuffer.byteOffset + fileBuffer.byteLength);

        // Encrypt the buffer
        const encryptionResult = await encryptionService.encryptFile(arrayBuffer);
        expect(encryptionResult).toHaveProperty("data");

        // Decrypt the buffer
        const decryptedBuffer = await encryptionService.decryptFile(encryptionResult.data);
        expect(decryptedBuffer).toBeInstanceOf(ArrayBuffer);

        // Convert decrypted buffer back to string
        const decryptedContent = encryptionService.arrayBufferToString(decryptedBuffer);
        expect(decryptedContent).toBe(testFileContent);
    });
});
