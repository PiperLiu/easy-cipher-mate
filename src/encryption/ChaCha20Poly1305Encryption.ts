import { createCipheriv, createDecipheriv, pbkdf2Sync, CipherCCMTypes, CipherCCMOptions, DecipherCCM } from 'crypto';
import { IEncryptionAlgorithm, EncryptionResult, IEncryptionAlgorithmConfig } from './IEncryptionAlgorithm';

export interface IChaCha20Poly1305EncryptionConfig extends IEncryptionAlgorithmConfig {
    password: string;
    salt: Buffer;
    nonce: Buffer;
}

export class ChaCha20Poly1305Encryption implements IEncryptionAlgorithm<IChaCha20Poly1305EncryptionConfig> {
    public static TAG_LENGTH = 16;
    public static KEY_LENGTH = 32;
    public static ITERATIONS = 100000;
    public static NONCE_LENGTH = 12;

    async encryptText(plaintext: string, config: IChaCha20Poly1305EncryptionConfig): Promise<EncryptionResult> {
        const { password, salt, nonce } = config;
        this.validateNonce(nonce);

        const key = this.deriveKey(password, salt);
        const cipher = createCipheriv('chacha20-poly1305', key, nonce, {
            authTagLength: ChaCha20Poly1305Encryption.TAG_LENGTH
        });

        const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();

        return { data: Buffer.concat([tag, encrypted]).buffer };
    }

    async decryptText(encryptedData: ArrayBuffer, config: IChaCha20Poly1305EncryptionConfig): Promise<string> {
        const { password, salt, nonce } = config;
        this.validateNonce(nonce);

        const key = this.deriveKey(password, salt);
        const data = Buffer.from(encryptedData);

        const tag = data.subarray(0, ChaCha20Poly1305Encryption.TAG_LENGTH);
        const ciphertext = data.subarray(ChaCha20Poly1305Encryption.TAG_LENGTH);

        const algorithm: CipherCCMTypes = 'chacha20-poly1305';
        const options: CipherCCMOptions = {
            authTagLength: ChaCha20Poly1305Encryption.TAG_LENGTH
        };

        const decipher = createDecipheriv(algorithm, key, nonce, options);

        decipher.setAuthTag(tag);

        return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    }


    async encryptFile(fileBuffer: ArrayBuffer, config: IChaCha20Poly1305EncryptionConfig): Promise<EncryptionResult> {
        return this.encryptText(Buffer.from(fileBuffer).toString('base64'), config);
    }

    async decryptFile(encryptedBuffer: ArrayBuffer, config: IChaCha20Poly1305EncryptionConfig): Promise<ArrayBuffer> {
        const decrypted = await this.decryptText(encryptedBuffer, config);
        return Buffer.from(decrypted, 'base64').buffer;
    }

    private deriveKey(password: string, salt: Buffer): Buffer {
        return pbkdf2Sync(
            password,
            salt,
            ChaCha20Poly1305Encryption.ITERATIONS,
            ChaCha20Poly1305Encryption.KEY_LENGTH,
            'sha256'
        );
    }

    private validateNonce(nonce: Buffer): void {
        if (nonce.length !== ChaCha20Poly1305Encryption.NONCE_LENGTH) {
            throw new Error(`Nonce must be ${ChaCha20Poly1305Encryption.NONCE_LENGTH} bytes`)
        }
    }
}

export class ChaCha20Poly1305EncryptionConfigFromEnv implements IChaCha20Poly1305EncryptionConfig {
    password: string;
    salt: Buffer;
    nonce: Buffer;

    constructor(password?: string) {
        this.password = password ?? '';

        this.salt = Buffer.from(
            process.env.ECM_CHACHA20_SALT || 'defaultsalt'.repeat(2),
            'base64'
        );

        this.nonce = process.env.ECM_CHACHA20_NONCE ?
            Buffer.from(process.env.ECM_CHACHA20_NONCE, 'base64') :
            Buffer.alloc(ChaCha20Poly1305Encryption.NONCE_LENGTH);

        if (this.nonce.length !== ChaCha20Poly1305Encryption.NONCE_LENGTH) {
            throw new Error('Nonce length in the environment variable is incorrect')
        }
    }
}
