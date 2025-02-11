import { IEncryptionAlgorithm, EncryptionResult, IEncryptionAlgorithmConfig } from '../encryption/IEncryptionAlgorithm';

export class EncryptionService {
    constructor(private algorithm: IEncryptionAlgorithm, private algorithmConfig: IEncryptionAlgorithmConfig) {}

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
}
