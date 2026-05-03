import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs/promises';
import bcrypt from 'bcryptjs';
import speakeasy from 'speakeasy';
import jwt from 'jsonwebtoken';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 4000;
const DATA_FILE = path.join(__dirname, 'user-store.json');
const JWT_SECRET = process.env.JWT_SECRET || 'deepsentinel-super-secret';

app.use(cors({ origin: 'http://localhost:5173' }));
app.use(express.json());

async function readStore() {
  try {
    const file = await fs.readFile(DATA_FILE, 'utf8');
    return JSON.parse(file);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return { users: [] };
    }
    throw error;
  }
}

async function writeStore(store) {
  await fs.writeFile(DATA_FILE, JSON.stringify(store, null, 2), 'utf8');
}

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const store = await readStore();
  const existing = store.users.find((user) => user.email === normalizedEmail);

  if (existing) {
    return res.status(409).json({ error: 'User already exists. Please log in instead.' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const secret = speakeasy.generateSecret({ name: `DeepSentinel (${normalizedEmail})` });

  const newUser = {
    email: normalizedEmail,
    passwordHash,
    totpSecret: secret.base32,
    createdAt: new Date().toISOString(),
  };

  store.users.push(newUser);
  await writeStore(store);

  res.json({ otpauthUrl: secret.otpauth_url, secret: secret.base32 });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const store = await readStore();
  const user = store.users.find((item) => item.email === normalizedEmail);

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  const passwordMatches = await bcrypt.compare(password, user.passwordHash);
  if (!passwordMatches) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  return res.json({ twoFactorRequired: true });
});

app.post('/api/auth/google', async (_req, res) => {
  const googleEmail = 'google-user@deepsentinel.com';
  const store = await readStore();
  let user = store.users.find((item) => item.email === googleEmail);

  if (!user) {
    const passwordHash = await bcrypt.hash('google-oauth-placeholder', 10);
    const secret = speakeasy.generateSecret({ name: `DeepSentinel (Google)` });

    user = {
      email: googleEmail,
      passwordHash,
      totpSecret: secret.base32,
      createdAt: new Date().toISOString(),
    };

    store.users.push(user);
    await writeStore(store);
  }

  const authToken = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token: authToken });
});

app.post('/api/auth/verify-otp', async (req, res) => {
  const { email, token } = req.body;
  if (!email || !token) {
    return res.status(400).json({ error: 'Email and OTP token are required.' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const store = await readStore();
  const user = store.users.find((item) => item.email === normalizedEmail);

  if (!user) {
    return res.status(401).json({ error: 'Invalid user.' });
  }

  const verified = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token,
    window: 1,
  });

  if (!verified) {
    return res.status(401).json({ error: 'Invalid two-factor authentication code.' });
  }

  const authToken = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token: authToken });
});

app.listen(PORT, () => {
  console.log(`Authentication server running on http://localhost:${PORT}`);
});
