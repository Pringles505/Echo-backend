const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs/promises');
const os = require('os');

const { persistImageDataUrl } = require('../src/interfaces/socket/context/imageStorage');

const ALLOWED = ['image/png', 'image/jpeg', 'image/webp'];

// Each test creates a unique workdir under the OS tmp dir so writes do not
// pollute the project's /uploads folder. We chdir back at the end.
async function withTmpCwd(fn) {
  const original = process.cwd();
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'echo-imgstore-'));
  process.chdir(dir);
  try {
    return await fn(dir);
  } finally {
    process.chdir(original);
    await fs.rm(dir, { recursive: true, force: true });
  }
}

// ----------------------------- happy paths -----------------------------

test('PNG data URL is written with .png extension', async () => {
  await withTmpCwd(async (dir) => {
    const url = await persistImageDataUrl({
      dataUrl: 'data:image/png;base64,iVBORw0KGgo=',
      allowedMimeTypes: ALLOWED,
      maxSize: 5_000_000,
      filenamePrefix: 'banner',
      userId: 'U1',
    });
    assert.match(url, /^\/uploads\/banner-U1-\d+\.png$/);
    const stat = await fs.stat(path.join(dir, 'uploads', path.basename(url)));
    assert.ok(stat.size > 0);
  });
});

test('JPEG data URL is written with .jpg extension (not .png)', async () => {
  await withTmpCwd(async () => {
    const url = await persistImageDataUrl({
      dataUrl: 'data:image/jpeg;base64,/9j/4AAQSkZJRg==',
      allowedMimeTypes: ALLOWED,
      maxSize: 5_000_000,
      filenamePrefix: 'profile',
      userId: 'U1',
    });
    assert.match(url, /^\/uploads\/profile-U1-\d+\.jpg$/);
  });
});

test('WebP data URL is written with .webp extension', async () => {
  await withTmpCwd(async () => {
    const url = await persistImageDataUrl({
      dataUrl: 'data:image/webp;base64,UklGRiQAAABXRUJQ',
      allowedMimeTypes: ALLOWED,
      maxSize: 5_000_000,
      filenamePrefix: 'banner',
      userId: 'U2',
    });
    assert.match(url, /^\/uploads\/banner-U2-\d+\.webp$/);
  });
});

// ----------------------------- validation -----------------------------

test('non-string input throws BadRequestError invalid_image', async () => {
  await assert.rejects(
    () => persistImageDataUrl({
      dataUrl: null,
      allowedMimeTypes: ALLOWED,
      maxSize: 5_000_000,
      filenamePrefix: 'banner',
      userId: 'U1',
    }),
    (err) => err.status === 400 && err.code === 'invalid_image'
  );
});

test('plain (non-data-URL) string throws invalid_image', async () => {
  await assert.rejects(
    () => persistImageDataUrl({
      dataUrl: 'http://example.com/img.png',
      allowedMimeTypes: ALLOWED,
      maxSize: 5_000_000,
      filenamePrefix: 'banner',
      userId: 'U1',
    }),
    (err) => err.status === 400 && err.code === 'invalid_image'
  );
});

test('SVG (non-allowed MIME) throws invalid_image_type', async () => {
  await assert.rejects(
    () => persistImageDataUrl({
      dataUrl: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDov',
      allowedMimeTypes: ALLOWED,
      maxSize: 5_000_000,
      filenamePrefix: 'banner',
      userId: 'U1',
    }),
    (err) => err.status === 400 && err.code === 'invalid_image_type'
  );
});

test('payload exceeding maxSize throws image_too_large', async () => {
  // base64 length 100 → ~75 bytes; set maxSize to 50 to trigger.
  const payload = 'A'.repeat(100);
  await assert.rejects(
    () => persistImageDataUrl({
      dataUrl: `data:image/png;base64,${payload}`,
      allowedMimeTypes: ALLOWED,
      maxSize: 50,
      filenamePrefix: 'banner',
      userId: 'U1',
    }),
    (err) => err.status === 400 && err.code === 'image_too_large'
  );
});
