import { AESGCMEncryption } from "../src/encryption/AESGCMEncryption";
import { EncryptionService } from "../src/services/EncryptionService";

// Increase the default timeout in case encryption/decryption takes a bit longer
jest.setTimeout(10000);

describe("EncryptionService using AESGCMEncryption", () => {
    const password = "test-password";
    const plaintext = "Hello, Unit Testing!";

    let encryptionService: EncryptionService;

    beforeAll(() => {
        const aesEncryption = new AESGCMEncryption();
        encryptionService = new EncryptionService(aesEncryption);
    });

    it("should encrypt and decrypt text correctly", async () => {
        // Encrypt the plaintext
        const encryptionResult = await encryptionService.encryptText(plaintext, password);
        expect(encryptionResult).toHaveProperty("data");
        expect(encryptionResult).toHaveProperty("iv");

        // Decrypt the ciphertext
        // In this test example, we assume that the salt is handled internally (or using a fixed salt for test purposes).
        const decryptedText = await encryptionService.decryptText(
            encryptionResult.data,
            encryptionResult.iv,
            encryptionResult.salt,
            password
        );

        expect(decryptedText).toBe(plaintext);
    });

});
