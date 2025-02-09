import { IEncryptionAlgorithm, EncryptionResult } from "./IEncryptionAlgorithm";

/**
 * Helper function to derive a CryptoKey from a password.
 */
async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

export class AESGCMEncryption implements IEncryptionAlgorithm {
    private saltLength = 16;

    async encryptText(plaintext: string, password: string): Promise<EncryptionResult> {
        const encoder = new TextEncoder();
        const salt = crypto.getRandomValues(new Uint8Array(this.saltLength));
        const key = await deriveKey(password, salt);
        const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM recommends a 12-byte IV
        const data = encoder.encode(plaintext);
        const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);

        // For simplicity, we can combine salt and ciphertext, or return salt separately.
        // Here we return the ciphertext with the IV; the caller must know the salt.
        // In a complete implementation, consider including the salt with the encrypted data.
        return { data: ciphertext, iv };
    }

    async decryptText(encryptedData: ArrayBuffer, iv: Uint8Array, password: string): Promise<string> {
        // In a full implementation, the salt should be extracted from the encrypted payload.
        // For this example, assume a fixed salt or have it provided externally.
        const salt = new Uint8Array(this.saltLength); // placeholder: replace with actual salt retrieval
        const key = await deriveKey(password, salt);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedData);
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    async encryptFile(fileBuffer: ArrayBuffer, password: string): Promise<EncryptionResult> {
        // The process is analogous to text encryption.
        const salt = crypto.getRandomValues(new Uint8Array(this.saltLength));
        const key = await deriveKey(password, salt);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, fileBuffer);
        return { data: ciphertext, iv };
    }

    async decryptFile(encryptedBuffer: ArrayBuffer, iv: Uint8Array, password: string): Promise<ArrayBuffer> {
        const salt = new Uint8Array(this.saltLength); // placeholder: replace with actual salt retrieval
        const key = await deriveKey(password, salt);
        return await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedBuffer);
    }
}
