import { encodeText, decodeText } from '../src/utils/encodingUtils';

describe('encodingUtils', () => {
  const testString = 'Hello, World! 123 ñáéíóú';
  const testStringAscii = 'Hello, World! 123 ??????';

  describe('encodeText and decodeText', () => {
    const encodings = ['utf-8', 'ascii', 'utf16le', 'base64', 'hex', 'latin1', 'binary'] as const;

    encodings.forEach(encoding => {
      it(`should correctly encode and decode with ${encoding}`, () => {
        const encoded = encodeText(testString, encoding);
        const decoded = decodeText(encoded, encoding);

        if (encoding === 'ascii') {
          // iconv-lite 的 ASCII 编码会直接过滤非 ASCII 字符
          expect(decoded).toBe(testStringAscii);
        } else {
          expect(decoded).toBe(testString);
        }
      });
    });
    it('should default to utf-8 if no encoding is specified', () => {
      const encoded = encodeText(testString);
      const decoded = decodeText(encoded);
      expect(decoded).toEqual(testString);
    });
  });

  describe('specific encoding behaviors', () => {
    it('base64 should produce valid base64 strings', () => {
      const encoded = encodeText('test string', 'base64');
      const decoded = decodeText(encoded, 'base64');
      expect(decoded).toBe('test string');

      const base64String = Buffer.from('test string').toString('base64');
      expect(Buffer.from(base64String, 'base64').toString()).toBe('test string');
    });

    it('hex should produce valid hex strings', () => {
      const encoded = encodeText('test', 'hex');
      const decoded = decodeText(encoded, 'hex');
      expect(decoded).toBe('test');

      const hexString = Buffer.from('test').toString('hex');
      expect(Buffer.from(hexString, 'hex').toString()).toBe('test');
    });
  });

  it('hex should produce valid hex strings', () => {
    const encoded = encodeText('test', 'hex');
    const decoded = decodeText(encoded, 'hex');
    expect(decoded).toEqual('test');
  });

  it('should handle empty strings', () => {
    const encodings = ['utf-8', 'ascii', 'utf16le', 'base64', 'hex', 'latin1', 'binary'] as const;

    encodings.forEach(encoding => {
      const encoded = encodeText('', encoding);
      const decoded = decodeText(encoded, encoding);
      expect(decoded).toEqual('');
    });
  });
});
