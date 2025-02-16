import { readFileSync } from 'fs';
import { deriveStringToUint8Array  } from '../utils/stringCoding';
import { IEncryptionAlgorithm, EncryptionResult, IEncryptionAlgorithmConfig } from './IEncryptionAlgorithm';

const DEFAULT_SALT = deriveStringToUint8Array('easy-cipher-mate', 16);
const DEFAULT_IV = deriveStringToUint8Array('easy-cipher-mate', 12);

export interface IAESGCMEncryptionConfig extends IEncryptionAlgorithmConfig {
    password: string;
    salt: Uint8Array;
    iv: Uint8Array;
}

export class AESGCMEncryption implements IEncryptionAlgorithm<IAESGCMEncryptionConfig> {
    async encryptText(plaintext: string, configuration: IAESGCMEncryptionConfig): Promise<EncryptionResult> {
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
        configuration: IAESGCMEncryptionConfig
    ): Promise<string> {
        const { password, salt, iv } = configuration;
        const key = await deriveKey(password, salt);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedData);
        return new TextDecoder().decode(decrypted);
    }

    async encryptFile(fileBuffer: ArrayBuffer, configuration: IAESGCMEncryptionConfig): Promise<EncryptionResult> {
        const { password, salt, iv } = configuration;
        const key = await deriveKey(password, salt);
        const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, fileBuffer);

        return {
            data: ciphertext,
        };
    }

    async decryptFile(
        encryptedBuffer: ArrayBuffer,
        configuration: IAESGCMEncryptionConfig
    ): Promise<ArrayBuffer> {
        const { password, salt, iv } = configuration;
        const key = await deriveKey(password, salt);
        return await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedBuffer);
    }
}

export class AESGCMEncryptionConfigFromEnv implements IAESGCMEncryptionConfig {
    password: string;
    salt: Uint8Array;
    iv: Uint8Array;

    constructor(
        password?: string,
        salt?: Uint8Array,
        iv?: Uint8Array
    ) {
        this.password = password ?? process.env.ECM_AESGCM_ENCRYPTION_PASSWORD ?? '';

        this.salt = salt ??
            (process.env.ECM_AESGCM_ENCRYPTION_SALT ?
                deriveStringToUint8Array(process.env.ECM_AESGCM_ENCRYPTION_SALT, 16) :
                DEFAULT_SALT
            );

        this.iv = iv ??
            (process.env.ECM_AESGCM_ENCRYPTION_IV ?
                deriveStringToUint8Array(process.env.ECM_AESGCM_ENCRYPTION_IV, 12) :
                DEFAULT_IV
            );
    }
}

export class AESGCMEncryptionConfigFromJSON implements IAESGCMEncryptionConfig {
    password: string;
    salt: Uint8Array;
    iv: Uint8Array;

    constructor(
        json: {
            password?: string;
            salt?: string;
            iv?: string;
        }
    ) {
        this.password = json.password ?? '';
        this.salt = json.salt ? deriveStringToUint8Array(json.salt, 16) : DEFAULT_SALT;
        this.iv = json.iv? deriveStringToUint8Array(json.iv, 12) : DEFAULT_IV;
    }
}

export class AESGCMEncryptionConfigFromJSONFile implements IAESGCMEncryptionConfig {
    password: string;
    salt: Uint8Array;
    iv: Uint8Array;

    constructor(
        filePath: string
    ) {
        const json = JSON.parse(readFileSync(filePath, 'utf-8'));
        this.password = json.password ?? '';
        this.salt = json.salt? deriveStringToUint8Array(json.salt, 16) : DEFAULT_SALT;
        this.iv = json.iv? deriveStringToUint8Array(json.iv, 12) : DEFAULT_IV;
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
