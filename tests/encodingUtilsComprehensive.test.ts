import { encodeText, decodeText } from '../src/utils/encodingUtils';

describe('encodingUtils comprehensive tests', () => {
  const testStrings = {
    ascii: 'Hello World 123',
    latin1: 'Hello, World! ñáéíóú',
    chinese: '你好，世界',
    japanese: 'こんにちは世界',
    emoji: '👋 Hello! 🌍',
    mixed: 'English 你好 こんにちは 👋'
  };

  const encodings = ['utf-8', 'ascii', 'utf16le', 'base64', 'hex', 'latin1', 'binary'] as const;

  describe('Round-trip encoding and decoding', () => {
    encodings.forEach(encoding => {
      it(`should correctly round-trip ASCII text with ${encoding} encoding`, () => {
        const encoded = encodeText(testStrings.ascii, encoding);
        const decoded = decodeText(encoded, encoding);

        if (encoding === 'ascii') {
          // ASCII should preserve all ASCII characters
          expect(decoded).toBe(testStrings.ascii);
        } else {
          expect(decoded).toBe(testStrings.ascii);
        }
      });

      it(`should handle Latin1 characters with ${encoding} encoding`, () => {
        const encoded = encodeText(testStrings.latin1, encoding);
        const decoded = decodeText(encoded, encoding);

        if (encoding === 'ascii') {
          // ASCII will lose non-ASCII chars
          expect(decoded).not.toBe(testStrings.latin1);
          // But should preserve ASCII part
          expect(decoded).toContain('Hello, World!');
        } else if (encoding === 'latin1' || encoding === 'binary') {
          // Latin1 should preserve Latin1 characters
          expect(decoded).toBe(testStrings.latin1);
        }
      });

      if (encoding === 'utf-8' || encoding === 'utf16le' || encoding === 'base64' || encoding === 'hex') {
        it(`should handle Unicode characters with ${encoding} encoding`, () => {
          // Test Chinese
          let encoded = encodeText(testStrings.chinese, encoding);
          let decoded = decodeText(encoded, encoding);
          expect(decoded).toBe(testStrings.chinese);

          // Test Japanese
          encoded = encodeText(testStrings.japanese, encoding);
          decoded = decodeText(encoded, encoding);
          expect(decoded).toBe(testStrings.japanese);

          // Test emoji
          encoded = encodeText(testStrings.emoji, encoding);
          decoded = decodeText(encoded, encoding);
          expect(decoded).toBe(testStrings.emoji);

          // Test mixed content
          encoded = encodeText(testStrings.mixed, encoding);
          decoded = decodeText(encoded, encoding);
          expect(decoded).toBe(testStrings.mixed);
        });
      }
    });
  });

  describe('Edge cases', () => {
    it('should handle empty strings', () => {
      encodings.forEach(encoding => {
        const encoded = encodeText('', encoding);
        const decoded = decodeText(encoded, encoding);
        expect(decoded).toBe('');
      });
    });

    it('should handle very long strings', () => {
      const longString = 'a'.repeat(10000);
      encodings.forEach(encoding => {
        const encoded = encodeText(longString, encoding);
        const decoded = decodeText(encoded, encoding);

        if (encoding === 'utf-8' || encoding === 'ascii' || encoding === 'utf16le' ||
          encoding === 'base64' || encoding === 'hex' || encoding === 'latin1' ||
          encoding === 'binary') {
          expect(decoded).toBe(longString);
        }
      });
    });
  });
});
