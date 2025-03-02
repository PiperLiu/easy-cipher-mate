import { writeFileSync, readFileSync, unlinkSync } from 'fs';
import { execSync } from 'child_process';
import path from 'path';

describe('CLI Text Encoding', () => {
  const testFilePath = path.join(__dirname, 'test-encoding.txt');
  const cliPath = 'node ' + path.resolve(__dirname, '../../lib/cli/index.js');

  const testTexts = {
    standard: 'Hello, World! 123',
    special: 'Hello, World! ñáéíóú', // Special characters
    chinese: '你好，世界',
    japanese: 'こんにちは世界'
  };

  const encodings = ['utf-8', 'latin1', 'utf16le'];
  const password = 'test-password';
  const algorithms = ['aes-gcm', 'chacha20-poly1305'];

  beforeEach(() => {
    // Start each test with a clean file
    try {
      unlinkSync(testFilePath);
    } catch (e) {
      // File may not exist, which is fine
    }
  });

  afterAll(() => {
    // Cleanup after all tests
    try {
      unlinkSync(testFilePath);
    } catch (e) {
      // File may not exist, which is fine
    }
  });

  describe.each(algorithms)('Algorithm: %s', (algorithm) => {
    describe.each(encodings)('Encoding: %s', (encoding) => {
      it('should encrypt and decrypt standard text', () => {
        // Write test content to file
        writeFileSync(testFilePath, testTexts.standard);

        // Encrypt the file
        execSync(`${cliPath} encrypt-text-file -f ${testFilePath} -p ${password} -a ${algorithm} -e ${encoding}`);

        // Encrypted content should be different from original
        const encryptedContent = readFileSync(testFilePath, 'utf-8');
        expect(encryptedContent).not.toBe(testTexts.standard);

        // Decrypt the file
        execSync(`${cliPath} decrypt-text-file -f ${testFilePath} -p ${password} -a ${algorithm} -e ${encoding}`);

        // Verify decrypted content matches original
        const decryptedContent = readFileSync(testFilePath, 'utf-8');
        expect(decryptedContent).toBe(testTexts.standard);
      });

      it('should handle special characters correctly', () => {
        // Only test special characters with encodings that support them
        if (encoding === 'utf-8' || encoding === 'utf16le') {
          writeFileSync(testFilePath, testTexts.special);

          execSync(`${cliPath} encrypt-text-file -f ${testFilePath} -p ${password} -a ${algorithm} -e ${encoding}`);
          execSync(`${cliPath} decrypt-text-file -f ${testFilePath} -p ${password} -a ${algorithm} -e ${encoding}`);

          const decryptedContent = readFileSync(testFilePath, 'utf-8');
          expect(decryptedContent).toBe(testTexts.special);
        }
      });

      it('should handle non-Latin characters correctly', () => {
        // Only test non-Latin characters with encodings that support them
        if (encoding === 'utf-8' || encoding === 'utf16le') {
          const testText = `${testTexts.chinese}\n${testTexts.japanese}`;
          writeFileSync(testFilePath, testText);

          execSync(`${cliPath} encrypt-text-file -f ${testFilePath} -p ${password} -a ${algorithm} -e ${encoding}`);
          execSync(`${cliPath} decrypt-text-file -f ${testFilePath} -p ${password} -a ${algorithm} -e ${encoding}`);

          const decryptedContent = readFileSync(testFilePath, 'utf-8');
          expect(decryptedContent).toBe(testText);
        }
      });
    });
  });

  it('should fail with incorrect password', () => {
    // Write test content to file
    writeFileSync(testFilePath, testTexts.standard);

    // Encrypt with one password
    execSync(`${cliPath} encrypt-text-file -f ${testFilePath} -p ${password} -a aes-gcm`);

    // Attempt to decrypt with wrong password should fail
    expect(() => {
      execSync(`${cliPath} decrypt-text-file -f ${testFilePath} -p wrong-password -a aes-gcm`, { stdio: 'pipe' });
    }).toThrow();
  });

  it('should handle empty lines correctly', () => {
    const testText = `line1\n\nline3`;
    writeFileSync(testFilePath, testText);

    execSync(`${cliPath} encrypt-text-file -f ${testFilePath} -p ${password} -a aes-gcm`);
    execSync(`${cliPath} decrypt-text-file -f ${testFilePath} -p ${password} -a aes-gcm`);

    const decryptedContent = readFileSync(testFilePath, 'utf-8');
    expect(decryptedContent).toBe(testText);
  });
});
