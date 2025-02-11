export interface EncryptionResult {
    data: ArrayBuffer; // the encrypted data
}

export interface IEncryptionAlgorithmConfig { }

export interface IEncryptionAlgorithm {
    /**
     * Encrypt a plaintext string.
     * @param plaintext The string to encrypt.
     * @param algorithmConfig The encryption algorithm configuration.
     */
    encryptText(plaintext: string, algorithmConfig: IEncryptionAlgorithmConfig): Promise<EncryptionResult>;

    /**
     * Decrypt an encrypted text.
     * @param encryptedData The ArrayBuffer containing the ciphertext.
     * @param algorithmConfig The encryption algorithm configuration.
     */
    decryptText(
        encryptedData: ArrayBuffer,
        algorithmConfig: IEncryptionAlgorithmConfig
    ): Promise<string>;

    /**
     * Encrypt a file (binary data).
     * @param fileBuffer The ArrayBuffer of file data.
     * @param algorithmConfig The encryption algorithm configuration.
     */
    encryptFile(fileBuffer: ArrayBuffer, algorithmConfig: IEncryptionAlgorithmConfig): Promise<EncryptionResult>;

    /**
     * Decrypt file data.
     * @param encryptedBuffer The ArrayBuffer of encrypted file data.
     * @param algorithmConfig The encryption algorithm configuration.
     */
    decryptFile(
        encryptedBuffer: ArrayBuffer,
        algorithmConfig: IEncryptionAlgorithmConfig
    ): Promise<ArrayBuffer>;
}
