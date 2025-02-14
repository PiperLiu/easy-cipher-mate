import { readFileSync } from 'fs';
import { IEncryptionAlgorithm, EncryptionResult, IEncryptionAlgorithmConfig } from './IEncryptionAlgorithm';

const DEFAULT_IV = new Uint8Array(12);
DEFAULT_IV.fill(0);

export interface IChaCha20Poly1305EncryptionConfig extends IEncryptionAlgorithmConfig {
    password: string;
    salt: Uint8Array;
    iv: Uint8Array;
}

export class ChaCha20Poly1305Encryption implements IEncryptionAlgorithm<IChaCha20Poly1305EncryptionConfig> {
    async encryptText(plaintext: string, configuration: IChaCha20Poly1305EncryptionConfig): Promise<EncryptionResult> {
        const { password, salt, iv } = configuration;
        const encoder = new TextEncoder();
        const key = await deriveKey(password, salt);
        const data = encoder.encode(plaintext);
        const ciphertext = await crypto.subtle.encrypt({ name: "chacha20-poly1305", iv }, key, data);

        return {
            data: ciphertext,
        };
    }

    async decryptText(
        encryptedData: ArrayBuffer,
        configuration: IChaCha20Poly1305EncryptionConfig
    ): Promise<string> {
        const { password, salt, iv } = configuration;
        const key = await deriveKey(password, salt);
        const decrypted = await crypto.subtle.decrypt({ name: "chacha20-poly1305", iv }, key, encryptedData);
        return new TextDecoder().decode(decrypted);
    }

    async encryptFile(fileBuffer: ArrayBuffer, configuration: IChaCha20Poly1305EncryptionConfig): Promise<EncryptionResult> {
        const { password, salt, iv } = configuration;
        const key = await deriveKey(password, salt);
        const ciphertext = await crypto.subtle.encrypt({ name: "chacha20-poly1305", iv }, key, fileBuffer);

        return {
            data: ciphertext,
        };
    }

    async decryptFile(
        encryptedBuffer: ArrayBuffer,
        configuration: IChaCha20Poly1305EncryptionConfig
    ): Promise<ArrayBuffer> {
        const { password, salt, iv } = configuration;
        const key = await deriveKey(password, salt);
        return await crypto.subtle.decrypt({ name: "chacha20-poly1305", iv }, key, encryptedBuffer);
    }
}

export class ChaCha20Poly1305EncryptionConfigFromEnv implements IChaCha20Poly1305EncryptionConfig {
    password: string;
    salt: Uint8Array;
    iv: Uint8Array;

    constructor(
        password?: string,
        salt?: Uint8Array,
        iv?: Uint8Array
    ) {
        this.password = password ?? process.env.ECM_CHACHA20POLY1305_ENCRYPTION_PASSWORD ?? '';
        this.salt = salt??
            (process.env.ECM_CHACHA20POLY1305_ENCRYPTION_SALT?
                new Uint8Array(Buffer.from(process.env.ECM_CHACHA20POLY1305_ENCRYPTION_SALT, 'base64')) :
                new Uint8Array(16)
            );
        this.iv = iv ??
            (process.env.ECM_CHACHA20POLY1305_ENCRYPTION_IV ?
                new Uint8Array(Buffer.from(process.env.ECM_CHACHA20POLY1305_ENCRYPTION_IV, 'base64')) :
                DEFAULT_IV
            );
    }
}

export class ChaCha20Poly1305EncryptionConfigFromJSON implements IChaCha20Poly1305EncryptionConfig {
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
        this.salt = json.salt? new Uint8Array(Buffer.from(json.salt, 'base64')) : new Uint8Array(16);
        this.iv = json.iv ? new Uint8Array(Buffer.from(json.iv, 'base64')) : DEFAULT_IV;
    }
}

export class ChaCha20Poly1305EncryptionConfigFromJSONFile implements IChaCha20Poly1305EncryptionConfig {
    password: string;
    salt: Uint8Array;
    iv: Uint8Array;

    constructor(
        filePath: string
    ) {
        const json = JSON.parse(readFileSync(filePath, 'utf-8'));
        this.password = json.password ?? '';
        this.salt = json.salt? new Uint8Array(Buffer.from(json.salt, 'base64')) : new Uint8Array(16);
        this.iv = json.iv ? new Uint8Array(Buffer.from(json.iv, 'base64')) : DEFAULT_IV;
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
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "ChaCha20", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}
