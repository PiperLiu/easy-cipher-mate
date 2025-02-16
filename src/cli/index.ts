#!/usr/bin/env node

import { Command } from 'commander';
import { readFileSync, writeFileSync } from 'fs';
import { AESGCMEncryption, AESGCMEncryptionConfigFromEnv } from '../encryption/AESGCMEncryption';
import { ChaCha20Poly1305Encryption, ChaCha20Poly1305EncryptionConfigFromEnv } from '../encryption/ChaCha20Poly1305Encryption';
import { EncryptionService } from '../services/EncryptionService';
import { IEncryptionAlgorithm, IEncryptionAlgorithmConfig } from '../encryption/IEncryptionAlgorithm';

function createEncryption(algorithm: string = 'aes-gcm'): [IEncryptionAlgorithm<any>, (password: string) => IEncryptionAlgorithmConfig] {
    switch (algorithm.toLowerCase()) {
        case 'chacha20-poly1305':
        case 'chacha20':
            return [
                new ChaCha20Poly1305Encryption(),
                (password: string) => new ChaCha20Poly1305EncryptionConfigFromEnv(password)
            ];
        case 'aes-gcm':
        case 'aes':
        default:
            return [
                new AESGCMEncryption(),
                (password: string) => new AESGCMEncryptionConfigFromEnv(password)
            ];
    }
}

const program = new Command();

program
    .name('easy-cipher-mate')
    .description('A CLI tool for file encryption/decryption')
    .version('1.0.0');

const encryptCommand = program
    .command('encrypt-file')
    .description('Encrypt a file')
    .requiredOption('-i, --input <path>', 'Input file path')
    .requiredOption('-o, --output <path>', 'Output file path')
    .requiredOption('-p, --password <string>', 'Encryption password')
    .option('-a, --algorithm <string>', 'Encryption algorithm (aes-gcm or chacha20-poly1305)', 'aes-gcm')
    .action(async (options) => {
        try {
            const [encryption, configFactory] = createEncryption(options.algorithm);
            const config = configFactory(options.password);
            const service = new EncryptionService(encryption, config);

            const fileBuffer = readFileSync(options.input);
            const result = await service.encryptFile(fileBuffer.buffer);

            writeFileSync(options.output, Buffer.from(result.data));
            console.log(`File encrypted successfully using ${options.algorithm}`);
        } catch (error: unknown) {
            console.error('Encryption failed:', error instanceof Error ? error.message : String(error));
            process.exit(1);
        }
    });

const decryptCommand = program
    .command('decrypt-file')
    .description('Decrypt a file')
    .requiredOption('-i, --input <path>', 'Input file path')
    .requiredOption('-o, --output <path>', 'Output file path')
    .requiredOption('-p, --password <string>', 'Decryption password')
    .option('-a, --algorithm <string>', 'Decryption algorithm (aes-gcm or chacha20-poly1305)', 'aes-gcm')
    .action(async (options) => {
        try {
            const [encryption, configFactory] = createEncryption(options.algorithm);
            const config = configFactory(options.password);
            const service = new EncryptionService(encryption, config);

            const encryptedData = readFileSync(options.input);
            const decrypted = await service.decryptFile(encryptedData.buffer);

            writeFileSync(options.output, Buffer.from(decrypted));
            console.log(`File decrypted successfully using ${options.algorithm}`);
        } catch (error: unknown) {
            console.error('Decryption failed:', error instanceof Error ? error.message : String(error));
            process.exit(1);
        }
    });

program.parse(process.argv);