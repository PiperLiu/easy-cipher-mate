import { IEncryptionAlgorithm, EncryptionResult, IEncryptionAlgorithmConfig } from '../encryption/IEncryptionAlgorithm';
import { readFileSync, writeFileSync } from 'fs';

export class EncryptionService {
    constructor(private algorithm: IEncryptionAlgorithm, private algorithmConfig: IEncryptionAlgorithmConfig) { }

    async encryptText(plaintext: string): Promise<EncryptionResult> {
        return this.algorithm.encryptText(plaintext, this.algorithmConfig);
    }

    async decryptText(encryptedData: ArrayBuffer): Promise<string> {
        return this.algorithm.decryptText(encryptedData, this.algorithmConfig);
    }

    async encryptFile(fileBuffer: ArrayBuffer): Promise<EncryptionResult> {
        return this.algorithm.encryptFile(fileBuffer, this.algorithmConfig);
    }

    async decryptFile(encryptedBuffer: ArrayBuffer): Promise<ArrayBuffer> {
        return this.algorithm.decryptFile(encryptedBuffer, this.algorithmConfig);
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
