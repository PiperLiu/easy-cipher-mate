import { createCipheriv, createDecipheriv, pbkdf2Sync } from 'crypto';
import { deriveStringToBuffer } from '../utils/stringCoding';
import { IEncryptionAlgorithm, EncryptionResult, IEncryptionAlgorithmConfig } from './IEncryptionAlgorithm';
import { encodeText, decodeText, TextEncoding } from '../utils/encodingUtils';

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
    textEncoding?: TextEncoding;
}

export class ChaCha20Poly1305Encryption implements IEncryptionAlgorithm<IChaCha20Poly1305EncryptionConfig> {
    public static TAG_LENGTH = DEFAULT_TAG_LENGTH;
    public static KEY_LENGTH = DEFAULT_KEY_LENGTH;
    public static ITERATIONS = DEFAULT_ITERATIONS;
    public static NONCE_LENGTH = DEFAULT_NONCE_LENGTH;

    async encryptText(plaintext: string, config: IChaCha20Poly1305EncryptionConfig, encoding?: TextEncoding): Promise<EncryptionResult> {
        const { password, salt, nonce, textEncoding = 'utf-8' } = config;
        this.validateNonce(nonce);

        const key = this.deriveKey(password, salt);
        const textBuffer = encodeText(plaintext, encoding ?? textEncoding);

        const cipher = createCipheriv('chacha20-poly1305', key, nonce, {
            authTagLength: ChaCha20Poly1305Encryption.TAG_LENGTH,
        });

        const encrypted = Buffer.concat([
            cipher.update(Buffer.from(textBuffer)),
            cipher.final()
        ]);
        const tag = cipher.getAuthTag();

        // return { data: finalBuffer.buffer.slice(finalBuffer.byteOffset, finalBuffer.byteOffset + finalBuffer.byteLength) };
        const finalBuffer = Buffer.concat([
            encrypted,
            tag,
        ])
        return { data: finalBuffer.buffer.slice(finalBuffer.byteOffset, finalBuffer.byteOffset + finalBuffer.byteLength) };
    }

    async decryptText(encryptedData: ArrayBuffer, config: IChaCha20Poly1305EncryptionConfig, encoding?: TextEncoding): Promise<string> {
        const { password, salt, nonce, textEncoding = 'utf-8' } = config;
        this.validateNonce(nonce);

        const key = this.deriveKey(password, salt);
        const data = Buffer.from(encryptedData);

        const tag = data.subarray(data.length - ChaCha20Poly1305Encryption.TAG_LENGTH);
        const ciphertext = data.subarray(0, data.length - ChaCha20Poly1305Encryption.TAG_LENGTH);

        const decipher = createDecipheriv('chacha20-poly1305', key, nonce, {
            authTagLength: ChaCha20Poly1305Encryption.TAG_LENGTH,
        })
        decipher.setAuthTag(tag);

        const decrypted = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]);

        return decodeText(
            decrypted.buffer.slice(decrypted.byteOffset, decrypted.byteOffset + decrypted.byteLength), encoding ?? textEncoding);
    }

    async encryptFile(fileBuffer: ArrayBuffer, config: IChaCha20Poly1305EncryptionConfig): Promise<EncryptionResult> {
        const { password, salt, nonce } = config;
        this.validateNonce(nonce);

        const key = this.deriveKey(password, salt);
        const dataBuffer = Buffer.from(fileBuffer);

        const cipher = createCipheriv('chacha20-poly1305', key, nonce, {
            authTagLength: ChaCha20Poly1305Encryption.TAG_LENGTH,
        })

        const encrypted = Buffer.concat([
            cipher.update(dataBuffer),
            cipher.final()
        ]);
        const tag = cipher.getAuthTag();

        const finalBuffer = Buffer.concat([
            encrypted,
            tag,
        ])

        return { data: finalBuffer.buffer.slice(finalBuffer.byteOffset, finalBuffer.byteOffset + finalBuffer.byteLength) };
    }

    async decryptFile(encryptedBuffer: ArrayBuffer, config: IChaCha20Poly1305EncryptionConfig): Promise<ArrayBuffer> {
        const { password, salt, nonce } = config;
        this.validateNonce(nonce);

        const key = this.deriveKey(password, salt);
        const data = Buffer.from(encryptedBuffer);

        const tag = data.subarray(data.length - ChaCha20Poly1305Encryption.TAG_LENGTH);
        const ciphertext = data.subarray(0, data.length - ChaCha20Poly1305Encryption.TAG_LENGTH);

        const decipher = createDecipheriv('chacha20-poly1305', key, nonce, {
            authTagLength: ChaCha20Poly1305Encryption.TAG_LENGTH,
        })
        decipher.setAuthTag(tag);

        const decrypted = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]);

        return decrypted.buffer.slice(decrypted.byteOffset, decrypted.byteOffset + decrypted.byteLength);
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

    public validateNonce(nonce: Buffer): void {
        if (nonce.length !== ChaCha20Poly1305Encryption.NONCE_LENGTH) {
            throw new Error(`Nonce must be ${ChaCha20Poly1305Encryption.NONCE_LENGTH} bytes`)
        }
    }
}

export class ChaCha20Poly1305EncryptionConfigFromEnv implements IChaCha20Poly1305EncryptionConfig {
    password: string;
    salt: Buffer;
    nonce: Buffer;
    textEncoding?: TextEncoding;

    constructor(
        password?: string,
        salt?: Buffer,
        nonce?: Buffer,
        textEncoding?: TextEncoding
    ) {
        this.password = password ?? process.env.ECM_CHACHA20_PASSWORD ?? '';

        this.salt = salt ?? (process.env.ECM_CHACHA20_SALT
            ? deriveStringToBuffer(process.env.ECM_CHACHA20_SALT, 16)
            : DEFAULT_SALT);

        if (nonce) {
            this.nonce = nonce;
        } else if (process.env.ECM_CHACHA20_NONCE) {
            this.nonce = deriveStringToBuffer(
                process.env.ECM_CHACHA20_NONCE,
                ChaCha20Poly1305Encryption.NONCE_LENGTH
            );
        } else {
            this.nonce = DEFAULT_NONCE;
        }

        this.textEncoding = textEncoding
            ?? (process.env.ECM_TEXT_ENCODING as TextEncoding)
            ?? 'utf-8';

        if (this.nonce.length !== ChaCha20Poly1305Encryption.NONCE_LENGTH) {
            throw new Error(`Length of nonce must be ${ChaCha20Poly1305Encryption.NONCE_LENGTH} bytes`)
        }
    }
}
