import { IEncryptionAlgorithm, EncryptionResult, IEncryptionAlgorithmConfig } from './IEncryptionAlgorithm';

const DEFAULT_SALT = new Uint8Array(16);
DEFAULT_SALT.fill(0);
const DEFAULT_IV = new Uint8Array(12);
DEFAULT_IV.fill(0);

export class AESGCMEncryptionConfig implements IEncryptionAlgorithmConfig {
    password: string;
    salt: Uint8Array;
    iv: Uint8Array;

    constructor(
        password: string,
        salt?: Uint8Array,
        iv?: Uint8Array
    ) {
        this.salt = salt ??
            (process.env.ECM_AESGCM_ENCRYPTION_SALT ?
                new Uint8Array(Buffer.from(process.env.ECM_AESGCM_ENCRYPTION_SALT, 'base64')) :
                DEFAULT_SALT
            );

        this.iv = iv ??
            (process.env.ECM_AESGCM_ENCRYPTION_IV ?
                new Uint8Array(Buffer.from(process.env.ECM_AESGCM_ENCRYPTION_IV, 'base64')) :
                DEFAULT_IV
            );

        this.password = password
    }
}

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

export class AESGCMEncryption implements IEncryptionAlgorithm<AESGCMEncryptionConfig> {
    async encryptText(plaintext: string, configuration: AESGCMEncryptionConfig): Promise<EncryptionResult> {
        const { password, salt, iv } = configuration;
        const encoder = new TextEncoder();
        const key = await deriveKey(password, salt);
        const data = encoder.encode(plaintext);
        const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);

        return {
            data: ciphertext,
        };
    }

    async decryptText(
        encryptedData: ArrayBuffer,
        configuration: AESGCMEncryptionConfig
    ): Promise<string> {
        const { password, salt, iv } = configuration;
        const key = await deriveKey(password, salt);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedData);
        return new TextDecoder().decode(decrypted);
    }

    async encryptFile(fileBuffer: ArrayBuffer, configuration: AESGCMEncryptionConfig): Promise<EncryptionResult> {
        const { password, salt, iv } = configuration;
        const key = await deriveKey(password, salt);
        const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, fileBuffer);

        return {
            data: ciphertext,
        };
    }

    async decryptFile(
        encryptedBuffer: ArrayBuffer,
        configuration: AESGCMEncryptionConfig
    ): Promise<ArrayBuffer> {
        const { password, salt, iv } = configuration;
        const key = await deriveKey(password, salt);
        return await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedBuffer);
    }
}
