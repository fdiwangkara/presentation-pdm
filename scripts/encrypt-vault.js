#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const crypto = globalThis.crypto;

// Load .env if present
const envPath = path.resolve(__dirname, '../.env');
let envPin = '2026';
if (fs.existsSync(envPath)) {
  const content = fs.readFileSync(envPath, 'utf-8');
  const match = content.match(/STUDENT_PIN\s*=\s*([^\r\n#]+)/);
  if (match) envPin = match[1].trim();
}

// Allow CLI argument override: node scripts/encrypt-vault.js 1234
const pin = process.argv[2] || envPin;
console.log(`🔐 Encrypting PDM Mentoring Vault with PIN: [${pin}]...`);

async function run() {
  const slidesDataPath = path.resolve(__dirname, '../public/slides_data.json');
  if (!fs.existsSync(slidesDataPath)) {
    console.error('❌ public/slides_data.json not found!');
    process.exit(1);
  }

  const slidesData = fs.readFileSync(slidesDataPath, 'utf-8');
  const enc = new TextEncoder();

  // Generate cryptographically random 16-byte salt and 12-byte IV
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Derive AES-GCM 256-bit key using PBKDF2 with 200,000 rounds
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(pin),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 200000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  // Encrypt slides data
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    enc.encode(slidesData)
  );

  // Compute a verification challenge: encrypting "PDM_VALID_ACCESS"
  const challengeCipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    enc.encode('PDM_VALID_ACCESS_GRANTED')
  );

  const payload = {
    algorithm: 'AES-256-GCM',
    kdf: 'PBKDF2-SHA256',
    iterations: 200000,
    salt: Buffer.from(salt).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    challenge: Buffer.from(challengeCipher).toString('base64'),
    data: Buffer.from(ciphertext).toString('base64'),
    updatedAt: new Date().toISOString()
  };

  const outputPath = path.resolve(__dirname, '../public/vault.enc.json');
  fs.writeFileSync(outputPath, JSON.stringify(payload, null, 2));

  // Also update .env if pin was passed via argument
  if (process.argv[2]) {
    fs.writeFileSync(envPath, `# Secret PIN for students to access the PDM Mentoring Presentation\nSTUDENT_PIN=${pin}\n`);
    console.log(`📝 Updated .env with new PIN.`);
  }

  console.log(`✅ Vault successfully encrypted!`);
  console.log(`📦 Ciphertext size: ${Buffer.byteLength(payload.data)} bytes`);
  console.log(`🔑 Current active PIN is: "${pin}"`);
}

run().catch(err => {
  console.error('Encryption failed:', err);
  process.exit(1);
});
