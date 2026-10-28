import { defineConfig } from 'vite';
import fs from 'fs';
import path from 'path';

export default defineConfig({
  server: {
    port: 3456,
    open: false,
    host: true
  },
  plugins: [
    {
      name: 'secure-pin-auth',
      configureServer(server) {
        // In-memory rate limiting map: ip -> { attempts, lockoutUntil }
        const rateLimits = new Map();

        server.middlewares.use('/api/verify-pin', (req, res) => {
          if (req.method !== 'POST') {
            res.statusCode = 405;
            res.end(JSON.stringify({ error: 'Method Not Allowed' }));
            return;
          }

          const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'client';
          const now = Date.now();
          const record = rateLimits.get(ip) || { attempts: 0, lockoutUntil: 0 };

          if (record.lockoutUntil > now) {
            const remainingSec = Math.ceil((record.lockoutUntil - now) / 1000);
            res.statusCode = 429;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ 
              error: `Terlalu banyak percobaan. Silakan coba lagi dalam ${remainingSec} detik.`,
              remainingSec 
            }));
            return;
          }

          let body = '';
          req.on('data', chunk => { body += chunk; });
          req.on('end', () => {
            try {
              const { pin } = JSON.parse(body || '{}');

              // Read current PIN from .env
              let expectedPin = '2026';
              const envPath = path.resolve(process.cwd(), '.env');
              if (fs.existsSync(envPath)) {
                const envContent = fs.readFileSync(envPath, 'utf-8');
                const match = envContent.match(/STUDENT_PIN\s*=\s*([^\r\n#]+)/);
                if (match) expectedPin = match[1].trim();
              }

              if (pin && pin.trim() === expectedPin) {
                // Reset rate limit on success
                rateLimits.delete(ip);
                res.statusCode = 200;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({ 
                  success: true, 
                  message: 'Akses Diberikan' 
                }));
              } else {
                record.attempts += 1;
                if (record.attempts >= 5) {
                  record.lockoutUntil = now + 30000; // 30 sec lockout
                  record.attempts = 0;
                }
                rateLimits.set(ip, record);

                res.statusCode = 401;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({ 
                  success: false, 
                  error: 'PIN salah! Silakan periksa kembali.',
                  attemptsLeft: Math.max(0, 5 - record.attempts)
                }));
              }
            } catch (err) {
              res.statusCode = 400;
              res.end(JSON.stringify({ error: 'Invalid JSON request' }));
            }
          });
        });
      }
    }
  ]
});
