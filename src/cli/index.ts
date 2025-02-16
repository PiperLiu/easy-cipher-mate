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

const encryptTextFileCommand = program
    .command('encrypt-text-file')
    .description('Encrypt a text file line by line')
    .requiredOption('-f, --file <path>', 'Text file path')
    .requiredOption('-p, --password <string>', 'Encryption password')
    .option('-a, --algorithm <string>', 'Encryption algorithm (aes-gcm or chacha20-poly1305)', 'aes-gcm')
    .action(async (options) => {
        try {
            const [encryption, configFactory] = createEncryption(options.algorithm);
            const config = configFactory(options.password);
            const service = new EncryptionService(encryption, config);

            const content = readFileSync(options.file, 'utf-8');
            const lines = content.split(/\r?\n/);
            
            const encryptedLines = await Promise.all(
                lines.map(async line => {
                    if (line.trim() === '') return line;
                    const result = await service.encryptText(line);
                    return Buffer.from(result.data).toString('base64');
                })
            );

            writeFileSync(options.file, encryptedLines.join('\n'));
            console.log(`File encrypted line by line successfully using ${options.algorithm}`);
        } catch (error: unknown) {
            console.error('Text file encryption failed:', error instanceof Error ? error.message : String(error));
            process.exit(1);
        }
    });

const decryptTextFileCommand = program
    .command('decrypt-text-file')
    .description('Decrypt a text file line by line')
    .requiredOption('-f, --file <path>', 'Text file path')
    .requiredOption('-p, --password <string>', 'Decryption password')
    .option('-a, --algorithm <string>', 'Decryption algorithm (aes-gcm or chacha20-poly1305)', 'aes-gcm')
    .action(async (options) => {
        try {
            const [encryption, configFactory] = createEncryption(options.algorithm);
            const config = configFactory(options.password);
            const service = new EncryptionService(encryption, config);

            const content = readFileSync(options.file, 'utf-8');
            const lines = content.split(/\r?\n/);
            
            const decryptedLines = await Promise.all(
                lines.map(async (line, index) => {
                    if (line.trim() === '') return line;
                    
                    try {
                        const buffer = Buffer.from(line, 'base64');
                        return await service.decryptText(buffer);
                    } catch (e) {
                        // If this is the first error we encounter, it might be due to wrong password
                        if (index === lines.findIndex(l => l.trim() !== '')) {
                            throw new Error('Invalid password');
                        }
                        // Otherwise, just return the original line
                        return line;
                    }
                })
            );

            writeFileSync(options.file, decryptedLines.join('\n'));
            console.log(`File decrypted line by line successfully using ${options.algorithm}`);
        } catch (error: unknown) {
            console.error('Text file decryption failed:', error instanceof Error ? error.message : String(error));
            process.exit(1);
        }
    });

program.parse(process.argv);