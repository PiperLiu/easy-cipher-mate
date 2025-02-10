export interface EncryptionResult {
    data: ArrayBuffer; // the encrypted data
}

export interface IEncryptionAlgorithm {
    /**
     * Encrypt a plaintext string.
     * @param plaintext The string to encrypt.
     * @param password The password used to derive the key.
     */
    encryptText(plaintext: string, password: string): Promise<EncryptionResult>;

    /**
     * Decrypt an encrypted text.
     * @param encryptedData The ArrayBuffer containing the ciphertext.
     * @param password The password used to derive the key.
     */
    decryptText(
        encryptedData: ArrayBuffer,
        password: string,
    ): Promise<string>;

    /**
     * Encrypt a file (binary data).
     * @param fileBuffer The ArrayBuffer of file data.
     * @param password The password used to derive the key.
     */
    encryptFile(fileBuffer: ArrayBuffer, password: string): Promise<EncryptionResult>;

    /**
     * Decrypt file data.
     * @param encryptedBuffer The ArrayBuffer of encrypted file data.
     * @param password The password used to derive the key.
     */
    decryptFile(
        encryptedBuffer: ArrayBuffer,
        password: string
    ): Promise<ArrayBuffer>;
}
