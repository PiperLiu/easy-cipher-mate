import { TextEncoding } from '../utils/encodingUtils';

export interface EncryptionResult {
    data: ArrayBuffer; // the encrypted data
}

export interface IEncryptionAlgorithmConfig {
    textEncoding?: TextEncoding;
}

export interface IEncryptionAlgorithm<T extends IEncryptionAlgorithmConfig> {
    /**
     * Encrypt a plaintext string.
     * @param plaintext The string to encrypt.
     * @param algorithmConfig The encryption algorithm configuration.
     * @param encoding The text encoding to use, defaults to `textEncoding` from the algorithm config.
     */
    // encryptText(plaintext: string, algorithmConfig: T, encoding?: TextEncoding): Promise<EncryptionResult>;
    encryptText(plaintext: string, algorithmConfig: T, encoding?: TextEncoding): Promise<EncryptionResult>;

    /**
     * Decrypt an encrypted text.
     * @param encryptedData The ArrayBuffer containing the ciphertext.
     * @param algorithmConfig The encryption algorithm configuration.
     * @param encoding The text encoding to use, defaults to `textEncoding` from the algorithm config.
     */
    decryptText(encryptedData: ArrayBuffer, algorithmConfig: T, encoding?: TextEncoding): Promise<string>;

    /**
     * Encrypt a file (binary data).
     * @param fileBuffer The ArrayBuffer of file data.
     * @param algorithmConfig The encryption algorithm configuration.
     * @param encoding The text encoding to use, defaults to `textEncoding` from the algorithm config.
     */
    encryptFile(fileBuffer: ArrayBuffer, algorithmConfig: T, encoding?: TextEncoding): Promise<EncryptionResult>;

    /**
     * Decrypt file data.
     * @param encryptedBuffer The ArrayBuffer of encrypted file data.
     * @param algorithmConfig The encryption algorithm configuration.
     * @param encoding The text encoding to use, defaults to `textEncoding` from the algorithm config.
     */ 
    decryptFile(encryptedBuffer: ArrayBuffer, algorithmConfig: T, encoding?: TextEncoding): Promise<ArrayBuffer>;
}

export type EncryptionConfigType<T> = T extends IEncryptionAlgorithm<infer C> ? C : never;
