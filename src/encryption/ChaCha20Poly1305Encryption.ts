import { createCipheriv, createDecipheriv, pbkdf2Sync, CipherCCMTypes, CipherCCMOptions } from 'crypto';
import { deriveStringToBuffer } from '../utils/stringCoding';
import { IEncryptionAlgorithm, EncryptionResult, IEncryptionAlgorithmConfig } from './IEncryptionAlgorithm';

const DEFAULT_TAG_LENGTH = 16;
const DEFAULT_KEY_LENGTH = 32;
const DEFAULT_ITERATIONS = 100000;
const DEFAULT_NONCE_LENGTH = 12;

const DEFAULT_SALT = deriveStringToBuffer('easy-cipher-mate', 16);
const DEFAULT_NONCE = deriveStringToBuffer('easy-cipher-mate', DEFAULT_NONCE_LENGTH);

export interface IChaCha20Poly1305EncryptionConfig extends IEncryptionAlgorithmConfig {
    password: string;
    salt: Buffer;
    nonce: Buffer;
}

export class ChaCha20Poly1305Encryption implements IEncryptionAlgorithm<IChaCha20Poly1305EncryptionConfig> {
    public static TAG_LENGTH = DEFAULT_TAG_LENGTH;
    public static KEY_LENGTH = DEFAULT_KEY_LENGTH;
    public static ITERATIONS = DEFAULT_ITERATIONS;
    public static NONCE_LENGTH = DEFAULT_NONCE_LENGTH;

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

    constructor(
        password?: string,
        salt?: Buffer,
        nonce?: Buffer
    ) {
        this.password = password ?? process.env.ECM_CHACHA20_PASSWORD?? '';

        this.salt = salt ??
            (process.env.ECM_CHACHA20_SALT ?
                deriveStringToBuffer(process.env.ECM_CHACHA20_SALT, 16) :
                DEFAULT_SALT
            )

        this.nonce = nonce ??
            (process.env.ECM_CHACHA20_NONCE ?
                deriveStringToBuffer(process.env.ECM_CHACHA20_NONCE, ChaCha20Poly1305Encryption.NONCE_LENGTH) :
                DEFAULT_NONCE
            )

        if (this.nonce.length !== ChaCha20Poly1305Encryption.NONCE_LENGTH) {
            throw new Error('Nonce length in the environment variable is incorrect')
        }
    }
}
