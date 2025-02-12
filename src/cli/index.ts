import { Command } from 'commander';
import { readFileSync, writeFileSync } from 'fs';
import { AESGCMEncryption } from '../encryption/AESGCMEncryption';
import { AESGCMEncryptionConfig } from '../encryption/AESGCMEncryption';
import { EncryptionService } from '../services/EncryptionService';

const program = new Command();

program
    .name('easy-cipher-mate')
    .description('A CLI tool for file encryption/decryption using AES-GCM')
    .version('1.0.0');

program
    .command('encrypt-file')
    .description('Encrypt a file')
    .requiredOption('-i, --input <path>', 'Input file path')
    .requiredOption('-o, --output <path>', 'Output file path')
    .requiredOption('-p, --password <string>', 'Encryption password')
    .action(async (options) => {
        try {
            const encryption = new AESGCMEncryption();
            const config = new AESGCMEncryptionConfig(options.password);
            const service = new EncryptionService(encryption, config);

            const fileBuffer = readFileSync(options.input);
            const result = await service.encryptFile(fileBuffer.buffer);

            writeFileSync(options.output, Buffer.from(result.data));
            console.log('File encrypted successfully');
        } catch (error: unknown) {
            console.error('Encryption failed:', error instanceof Error ? error.message : String(error));
            process.exit(1);
        }
    });

program
    .command('decrypt-file')
    .description('Decrypt a file')
    .requiredOption('-i, --input <path>', 'Input file path')
    .requiredOption('-o, --output <path>', 'Output file path')
    .requiredOption('-p, --password <string>', 'Decryption password')
    .action(async (options) => {
        try {
            const encryption = new AESGCMEncryption();
            const config = new AESGCMEncryptionConfig(options.password);
            const service = new EncryptionService(encryption, config);

            const encryptedData = readFileSync(options.input);
            const decrypted = await service.decryptFile(encryptedData.buffer);

            writeFileSync(options.output, Buffer.from(decrypted));
            console.log('File decrypted successfully');
        } catch (error: unknown) {
            console.error('Decryption failed:', error instanceof Error ? error.message : String(error));
            process.exit(1);
        }
    });

program.parse(process.argv);