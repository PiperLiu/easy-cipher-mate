import { AESGCMEncryption, AESGCMEncryptionConfig } from "../src/encryption/AESGCMEncryption";
import { EncryptionService } from "../src/services/EncryptionService";

// Increase the default timeout in case encryption/decryption takes a bit longer
jest.setTimeout(10000);

describe("EncryptionService using AESGCMEncryption", () => {
    const password = "test-password";
    const plaintext = "Hello, Unit Testing!";

    let encryptionService: EncryptionService<AESGCMEncryption, AESGCMEncryptionConfig>;

    beforeAll(() => {
        const aesEncryption = new AESGCMEncryption();
        const aesEncryptionConfig = new AESGCMEncryptionConfig(password);
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

});
