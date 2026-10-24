import { describe, expect, it } from 'vitest';
import { inspectImage } from '../lib/image';

const bytes = (b64: string) => new Uint8Array(Buffer.from(b64, 'base64'));

const JPEG = '/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAAVACUDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDkaKKK+8PmAooooAKKKKACiiigAooooAKKKKAP/9k=';
const PNG = 'iVBORw0KGgoAAAANSUhEUgAAACUAAAAVCAIAAABOhrD5AAAAJklEQVR4nGMUiTrBQEfARE/LRu0btW/UvlH7Ru0btW/UvlH7qAAA58UBYCwanx8AAAAASUVORK5CYII=';
const WEBP = 'UklGRkoAAABXRUJQVlA4ID4AAABwAwCdASolABUAPm02l0ikIyIhJWgAgA2JZwB2APwAAGNXwvAA/vAb3//9Js8TZ4mz5JH//ylXgsbm+AAAAA==';
const WEBP_L = 'UklGRh4AAABXRUJQVlA4TBEAAAAvJAAFAAdQrVIUuf+BiOh/AAA=';
const JPEG_P = '/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wgARCAAeACgDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAb/xAAVAQEBAAAAAAAAAAAAAAAAAAAAAf/aAAwDAQACEAMQAAABgAgAAAAH/8QAFBABAAAAAAAAAAAAAAAAAAAAQP/aAAgBAQABBQIn/8QAFBEBAAAAAAAAAAAAAAAAAAAAIP/aAAgBAwEBPwFf/8QAFBEBAAAAAAAAAAAAAAAAAAAAIP/aAAgBAgEBPwFf/8QAFBABAAAAAAAAAAAAAAAAAAAAQP/aAAgBAQAGPwIn/8QAFBABAAAAAAAAAAAAAAAAAAAAQP/aAAgBAQABPyEn/9oADAMBAAIAAwAAABAMMMMMP//EABQRAQAAAAAAAAAAAAAAAAAAACD/2gAIAQMBAT8QX//EABQRAQAAAAAAAAAAAAAAAAAAACD/2gAIAQIBAT8QX//EABQQAQAAAAAAAAAAAAAAAAAAAED/2gAIAQEAAT8QJ//Z';

describe('inspectImage', () => {
  it('reads a JPEG', () => expect(inspectImage(bytes(JPEG))).toEqual({ type: 'image/jpeg', width: 37, height: 21 }));
  it('reads a progressive JPEG', () => expect(inspectImage(bytes(JPEG_P))).toEqual({ type: 'image/jpeg', width: 40, height: 30 }));
  it('reads a PNG', () => expect(inspectImage(bytes(PNG))).toEqual({ type: 'image/png', width: 37, height: 21 }));
  it('reads a lossy WebP', () => expect(inspectImage(bytes(WEBP))).toEqual({ type: 'image/webp', width: 37, height: 21 }));
  it('reads a lossless WebP', () => expect(inspectImage(bytes(WEBP_L))).toEqual({ type: 'image/webp', width: 37, height: 21 }));
  it('refuses an SVG', () => expect(inspectImage(new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'))).toBeNull());
  it('refuses HTML named as a picture', () => expect(inspectImage(new TextEncoder().encode('<!doctype html><html><body>hello</body></html>'))).toBeNull());
  it('refuses a GIF', () => expect(inspectImage(new TextEncoder().encode('GIF89a' + 'x'.repeat(40)))).toBeNull());
  it('refuses a cut off file', () => expect(inspectImage(bytes(PNG).slice(0, 12))).toBeNull());
  it('refuses an empty file', () => expect(inspectImage(new Uint8Array())).toBeNull());
});
