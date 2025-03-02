import { IEncryptionAlgorithm, EncryptionResult, EncryptionConfigType } from '../encryption/IEncryptionAlgorithm';
import { readFileSync, writeFileSync } from 'fs';
import { TextEncoding } from '../utils/encodingUtils';

export class EncryptionService<
    TAlgorithm extends IEncryptionAlgorithm<any>,
    TConfig extends EncryptionConfigType<TAlgorithm>
> {
    constructor(private algorithm: TAlgorithm, private algorithmConfig: TConfig) { }

    async encryptText(plaintext: string, encoding?: TextEncoding): Promise<EncryptionResult> {
        return this.algorithm.encryptText(plaintext, this.algorithmConfig, encoding);
    }

    async decryptText(encryptedData: ArrayBuffer, encoding?: TextEncoding): Promise<string> {
        return this.algorithm.decryptText(encryptedData, this.algorithmConfig, encoding);
    }

    async encryptFile(fileBuffer: ArrayBuffer, encoding?: TextEncoding): Promise<EncryptionResult> {
        return this.algorithm.encryptFile(fileBuffer, this.algorithmConfig, encoding);
    }

    async decryptFile(encryptedBuffer: ArrayBuffer, encoding?: TextEncoding): Promise<ArrayBuffer> {
        return this.algorithm.decryptFile(encryptedBuffer, this.algorithmConfig, encoding);
    }

    async encryptFileByName(fileName: string): Promise<EncryptionResult> {
        const fileBuffer = readFileSync(fileName);
        const arrayBuffer = fileBuffer.buffer.slice(fileBuffer.byteOffset, fileBuffer.byteOffset + fileBuffer.byteLength);
        return this.encryptFile(arrayBuffer);
    }

    async decryptFileByName(encryptedResult: EncryptionResult, fileName: string): Promise<void> {
        const decryptedBuffer = await this.decryptFile(encryptedResult.data);
        const uint8Array = new Uint8Array(decryptedBuffer);
        writeFileSync(fileName, uint8Array);
    }

    arrayBufferToString(buffer: ArrayBuffer): string {
        const decoder = new TextDecoder('utf-8');
        return decoder.decode(buffer);
    }

    stringToArrayBuffer(str: string): ArrayBuffer {
        const encoder = new TextEncoder();
        return encoder.encode(str).buffer;
    }
}
