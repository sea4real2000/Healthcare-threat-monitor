/** Reads the type and pixel size of a picture from its first bytes. Returns null for anything that is not a JPEG, PNG or WebP. */
export type ImageInfo = { type: 'image/jpeg' | 'image/png' | 'image/webp'; width: number; height: number };

const PNG_HEAD = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

export function inspectImage(b: Uint8Array): ImageInfo | null {
  const buf = Buffer.from(b.buffer, b.byteOffset, b.byteLength);
  const ok = (info: ImageInfo) => (info.width > 0 && info.height > 0 && info.width <= 20000 && info.height <= 20000 ? info : null);

  if (buf.length >= 24 && PNG_HEAD.every((v, i) => buf[i] === v) && buf.toString('latin1', 12, 16) === 'IHDR') {
    return ok({ type: 'image/png', width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) });
  }

  if (buf.length >= 30 && buf.toString('latin1', 0, 4) === 'RIFF' && buf.toString('latin1', 8, 12) === 'WEBP') {
    const kind = buf.toString('latin1', 12, 16);
    if (kind === 'VP8X') return ok({ type: 'image/webp', width: 1 + buf.readUIntLE(24, 3), height: 1 + buf.readUIntLE(27, 3) });
    if (kind === 'VP8 ' && buf[23] === 0x9d && buf[24] === 0x01 && buf[25] === 0x2a) {
      return ok({ type: 'image/webp', width: buf.readUInt16LE(26) & 0x3fff, height: buf.readUInt16LE(28) & 0x3fff });
    }
    if (kind === 'VP8L' && buf[20] === 0x2f) {
      const bits = buf.readUInt32LE(21);
      return ok({ type: 'image/webp', width: 1 + (bits & 0x3fff), height: 1 + ((bits >> 14) & 0x3fff) });
    }
    return null;
  }

  if (buf.length >= 4 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    // Walk the segments until the frame header, which carries the size.
    let at = 2;
    while (at + 9 < buf.length) {
      if (buf[at] !== 0xff) return null;
      const marker = buf[at + 1];
      if (marker === 0xff) {
        at += 1;
        continue;
      }
      if (marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) {
        at += 2;
        continue;
      }
      const length = buf.readUInt16BE(at + 2);
      if (length < 2) return null;
      const isFrame = marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc;
      if (isFrame) return ok({ type: 'image/jpeg', width: buf.readUInt16BE(at + 7), height: buf.readUInt16BE(at + 5) });
      at += 2 + length;
    }
    return null;
  }
  return null;
}
