import { IEncryptionAlgorithm, EncryptionResult } from './IEncryptionAlgorithm';

interface EncryptionConfig {
    salt: Uint8Array
    iv: Uint8Array
}

const DEFAULT_SALT = new Uint8Array(16)
DEFAULT_SALT.fill(0)
const DEFAULT_IV = new Uint8Array(12)
DEFAULT_IV.fill(0)

export const getEncryptionConfig = (): EncryptionConfig => {
    const envSalt = process.env.ECM_AESGCM_ENCRYPTION_SALT
    const envIv = process.env.ECM_ENCRYPTION_IV

    return {
        salt: envSalt ?
            new Uint8Array(Buffer.from(envSalt, 'base64')) :
            DEFAULT_SALT
        ,
        iv: envIv ?
            new Uint8Array(Buffer.from(envIv, 'base64')) :
            DEFAULT_IV
    }
}

async function deriveKey(password: string): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const { salt } = getEncryptionConfig();

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
    async encryptText(plaintext: string, password: string): Promise<EncryptionResult> {
        const encoder = new TextEncoder();
        const key = await deriveKey(password);
        const iv = getEncryptionConfig().iv;
        const data = encoder.encode(plaintext);
        const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);

        return {
            data: ciphertext,
        };
    }

    async decryptText(
        encryptedData: ArrayBuffer,
        password: string
    ): Promise<string> {
        const key = await deriveKey(password);
        const iv = getEncryptionConfig().iv;
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedData);
        return new TextDecoder().decode(decrypted);
    }

    async encryptFile(fileBuffer: ArrayBuffer, password: string): Promise<EncryptionResult> {
        const key = await deriveKey(password);
        const iv = getEncryptionConfig().iv;
        const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, fileBuffer);

        return {
            data: ciphertext,
        };
    }

    async decryptFile(
        encryptedBuffer: ArrayBuffer,
        password: string
    ): Promise<ArrayBuffer> {
        const key = await deriveKey(password);
        const iv = getEncryptionConfig().iv;
        return await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedBuffer);
    }
}
