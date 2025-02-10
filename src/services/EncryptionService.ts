import { IEncryptionAlgorithm, EncryptionResult } from '../encryption/IEncryptionAlgorithm';

export class EncryptionService {
    constructor(private algorithm: IEncryptionAlgorithm) {}

    async encryptText(plaintext: string, password: string): Promise<EncryptionResult> {
        return this.algorithm.encryptText(plaintext, password);
    }

    async decryptText(encryptedData: ArrayBuffer, password: string): Promise<string> {
        return this.algorithm.decryptText(encryptedData, password);
    }

    async encryptFile(fileBuffer: ArrayBuffer, password: string): Promise<EncryptionResult> {
        return this.algorithm.encryptFile(fileBuffer, password);
    }

    async decryptFile(encryptedBuffer: ArrayBuffer, password: string): Promise<ArrayBuffer> {
        return this.algorithm.decryptFile(encryptedBuffer, password);
    }
}
