import { IEncryptionAlgorithm, EncryptionResult } from "../encryption/IEncryptionAlgorithm";

export class EncryptionService {
    private algorithm: IEncryptionAlgorithm;

    constructor(algorithm: IEncryptionAlgorithm) {
        this.algorithm = algorithm;
    }

    setAlgorithm(algorithm: IEncryptionAlgorithm) {
        this.algorithm = algorithm;
    }

    encryptText(plaintext: string, password: string): Promise<EncryptionResult> {
        return this.algorithm.encryptText(plaintext, password);
    }

    decryptText(encryptedData: ArrayBuffer, iv: Uint8Array, password: string): Promise<string> {
        return this.algorithm.decryptText(encryptedData, iv, password);
    }

    encryptFile(fileBuffer: ArrayBuffer, password: string): Promise<EncryptionResult> {
        return this.algorithm.encryptFile(fileBuffer, password);
    }

    decryptFile(encryptedBuffer: ArrayBuffer, iv: Uint8Array, password: string): Promise<ArrayBuffer> {
        return this.algorithm.decryptFile(encryptedBuffer, iv, password);
    }
}
