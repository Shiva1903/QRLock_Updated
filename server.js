const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const forge = require('node-forge');
const secrets = require('secrets.js');
const QRCode = require('qrcode');
const { PNG } = require('pngjs');
const nodemailer = require('nodemailer');
const adminRouter = require('./admin');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3002;

app.use(session({
  secret: 'sessionSecret',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 600000 },
  rolling: true
}));
app.use('/system-core-access-106014491553', adminRouter);
app.use(express.static(path.join(__dirname, 'public')));

const qrDir = path.join(__dirname, 'qrcodes');
if (!fs.existsSync(qrDir)) fs.mkdirSync(qrDir);
app.use('/qrcodes', express.static(qrDir));

const upload = multer({ storage: multer.memoryStorage() });
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
const dbPath = path.join(__dirname, "database.sqlite");
const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database at:', dbPath);
  }
});
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    gmail TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key_pem TEXT,
    private_key_pem TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS pending_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    gmail TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key_pem TEXT,
    private_key_pem TEXT,
    token TEXT NOT NULL,
    token_expires_at INTEGER NOT NULL,
    used INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uploader_id INTEGER,
    original_filename TEXT,
    qr_code_path TEXT,
    json_payload TEXT,
    recipients TEXT,
    threshold INTEGER,
    file_id TEXT,
    downloads TEXT DEFAULT '[]'
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS account_deletion_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

(async () => {
  try {
    const adminEmail = process.env.ADMIN_EMAIL || "shivasomucsc@gmail.com";
    const adminPassword = process.env.ADMIN_PASSWORD || "Xj8#z1Qp@960!LmD";
    // Check if admin user already exists
    const existingAdmin = await dbGet("SELECT * FROM users WHERE gmail=?", [adminEmail]);
    if (!existingAdmin) {
      // Insert a new admin user with no RSA keys
      const adminHash = hashPassword(adminPassword);
      await dbRun(
        `INSERT INTO users (gmail, username, password_hash, public_key_pem, private_key_pem)
         VALUES (?, ?, ?, ?, ?)`,
        [adminEmail, "Admin", adminHash, "", ""]
      );
      console.log("Admin user created with email:", adminEmail);
    } else {
      console.log("Admin user already exists:", adminEmail);
    }
  } catch (err) {
    console.error("Error ensuring admin user:", err);
  }
})();

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err); else resolve(this.lastID);
    });
  });
}
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => { if (err) reject(err); else resolve(row); });
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => { if (err) reject(err); else resolve(rows); });
  });
}

function isStrongPassword(password) {
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return regex.test(password);
}

function generateRSAKeyPair(bits = 2048) {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits, workers: -1 }, (err, keypair) => {
      if (err) return reject(err);
      const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
      const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
      resolve({ privateKeyPem, publicKeyPem });
    });
  });
}
function hashPassword(password) {
  const salt = bcrypt.genSaltSync(10);
  return bcrypt.hashSync(password, salt);
}
function checkPassword(storedHash, candidate) {
  return bcrypt.compareSync(candidate, storedHash);
}
function aesEncrypt(dataBuf, keyBuf) {
  const iv = forge.random.getBytesSync(12);
  const cipher = forge.cipher.createCipher('AES-GCM', keyBuf.toString('binary'));
  cipher.start({ iv });
  cipher.update(forge.util.createBuffer(dataBuf));
  cipher.finish();
  const ciphertext = cipher.output.getBytes();
  const tag = cipher.mode.tag.getBytes();
  return { ciphertext: Buffer.from(ciphertext, 'binary'), iv: Buffer.from(iv, 'binary'), tag: Buffer.from(tag, 'binary') };
}
function aesDecrypt(ciphertextBuf, keyBuf, ivBuf, tagBuf) {
  const decipher = forge.cipher.createDecipher('AES-GCM', keyBuf.toString('binary'));
  decipher.start({ iv: ivBuf.toString('binary'), tag: forge.util.createBuffer(tagBuf.toString('binary')) });
  decipher.update(forge.util.createBuffer(ciphertextBuf));
  if (!decipher.finish()) throw new Error("AES-GCM authentication failed");
  const plain = decipher.output.getBytes();
  return Buffer.from(plain, 'binary');
}
function rsaEncrypt(publicKeyPem, dataBuf) {
  const pubKey = forge.pki.publicKeyFromPem(publicKeyPem);
  const encrypted = pubKey.encrypt(dataBuf.toString('binary'), 'RSA-OAEP', { md: forge.md.sha256.create() });
  return Buffer.from(encrypted, 'binary');
}
function rsaDecrypt(privateKeyPem, encBuf) {
  const privKey = forge.pki.privateKeyFromPem(privateKeyPem);
  const decrypted = privKey.decrypt(encBuf.toString('binary'), 'RSA-OAEP', { md: forge.md.sha256.create() });
  return Buffer.from(decrypted, 'binary');
}
function splitSecret(keyHex, totalShares, threshold) {
  return secrets.share(keyHex, totalShares, threshold);
}
function recoverSecret(sharesArr) {
  return secrets.combine(sharesArr);
}

function embedPayloadLSB(imageBuffer, payloadStr) {
  return new Promise((resolve, reject) => {
    const payloadBuffer = Buffer.from(payloadStr, 'utf8');
    const payloadLength = payloadBuffer.length;
    let payloadBits = [];
    for (let i = 3; i >= 0; i--) {
      const byte = (payloadLength >> (i * 8)) & 0xFF;
      for (let bit = 7; bit >= 0; bit--) {
        payloadBits.push((byte >> bit) & 1);
      }
    }
    for (let i = 0; i < payloadBuffer.length; i++) {
      for (let bit = 7; bit >= 0; bit--) {
        payloadBits.push((payloadBuffer[i] >> bit) & 1);
      }
    }
    let png;
    try {
      png = PNG.sync.read(imageBuffer);
    } catch (err) {
      return reject(new Error("Failed to read PNG image."));
    }
    const pixelCount = png.width * png.height;
    if (payloadBits.length > pixelCount) return reject(new Error("Payload too large to embed in image."));
    for (let i = 0; i < payloadBits.length; i++) {
      const idx = i * 4;
      png.data[idx] = (png.data[idx] & 0xFE) | payloadBits[i];
    }
    const outputBuffer = PNG.sync.write(png);
    resolve(outputBuffer);
  });
}
async function embedPayloadInQRCodeLSB(payloadStr, fillerMessage) {
  const qrBuffer = await QRCode.toBuffer(fillerMessage, { type: 'png' });
  const stegoBuffer = await embedPayloadLSB(qrBuffer, payloadStr);
  return stegoBuffer;
}
function extractPayloadLSB(imageBuffer) {
  const png = PNG.sync.read(imageBuffer);
  const pixelCount = png.width * png.height;
  if (pixelCount < 32) throw new Error("Image too small to contain payload header.");
  let headerBits = [];
  for (let i = 0; i < 32; i++) {
    const idx = i * 4;
    headerBits.push(png.data[idx] & 1);
  }
  let payloadLength = 0;
  for (let i = 0; i < 32; i++) {
    payloadLength = (payloadLength << 1) | headerBits[i];
  }
  const totalPayloadBits = payloadLength * 8;
  if (pixelCount < 32 + totalPayloadBits) throw new Error("Image does not contain full payload.");
  let payloadBits = [];
  for (let i = 32; i < 32 + totalPayloadBits; i++) {
    const idx = i * 4;
    payloadBits.push(png.data[idx] & 1);
  }
  const payloadBuffer = Buffer.alloc(payloadLength);
  for (let i = 0; i < payloadLength; i++) {
    let byte = 0;
    for (let bit = 0; bit < 8; bit++) {
      byte = (byte << 1) | payloadBits[i * 8 + bit];
    }
    payloadBuffer[i] = byte;
  }
  return payloadBuffer.toString('utf8');
}

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}
const globalDecryptionPool = {};
const globalOTPStore = {};
const globalReconstructedKey = {};

function serveTemplate(res, templatePath, replacements) {
  fs.readFile(templatePath, 'utf8', (err, data) => {
    if (err) return res.status(500).send("Error loading template.");
    let output = data;
    for (let key in replacements) {
      const token = new RegExp(`{{\\s*${key}\\s*}}`, 'g');
      output = output.replace(token, replacements[key]);
    }
    res.send(output);
  });
}
function sendMessage(res, message, link, linkText) {
  serveTemplate(res, path.join(__dirname, 'views', 'message.html'), { message, link, linkText });
}

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'views', 'home.html')); });
app.get('/home', (req, res) => { res.sendFile(path.join(__dirname, 'views', 'home.html')); });
app.get('/register', (req, res) => { res.sendFile(path.join(__dirname, 'views', 'register.html')); });
app.post('/register', async (req, res) => {
  try {
    const { gmail, username, password } = req.body;
    if (!gmail || !username || !password) return res.sendFile(path.join(__dirname, 'views', 'register.html'));
    if (!isStrongPassword(password)) return sendMessage(res, "Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.", "/register", "Back");
    const existingUser = await dbGet(`SELECT * FROM users WHERE gmail=? OR username=?`, [gmail, username]);
    const existingPending = await dbGet(`SELECT * FROM pending_users WHERE gmail=? OR username=?`, [gmail, username]);
    if (existingUser || existingPending) return sendMessage(res, "Email or Username already registered. Please try again.", "/register", "Back");
    const { privateKeyPem, publicKeyPem } = await generateRSAKeyPair();
    const passHash = hashPassword(password);
    const token = crypto.randomBytes(20).toString('hex');
    const tokenExpiresAt = Date.now() + 300000;
    await dbRun(`INSERT INTO pending_users (gmail, username, password_hash, public_key_pem, private_key_pem, token, token_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [gmail, username, passHash, publicKeyPem, privateKeyPem, token, tokenExpiresAt]);
    const confirmLink = `http://${req.headers.host}/confirm?token=${token}`;
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: gmail,
      subject: 'QRLock Registration Confirmation',
      text: `Please confirm your registration by clicking the following link: ${confirmLink}\nThis link expires in 5 minutes.`
    };
    transporter.sendMail(mailOptions, (error, info) => { if (error) console.error('Email sending error: ', error); else console.log('Confirmation email sent: ' + info.response); });
    sendMessage(res, "Thank you for registering. Please check your Gmail for a confirmation link to complete your registration.", "/home", "Back to Home");
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error during registration: ${err.message}`, "/register", "Back");
  }
});
app.get('/confirm', async (req, res) => {
  const { token } = req.query;
  if (!token) return sendMessage(res, "Invalid confirmation link.", "/register", "Register");
  try {
    const pendingUser = await dbGet(`SELECT * FROM pending_users WHERE token=? AND used=0`, [token]);
    if (!pendingUser || Date.now() > pendingUser.token_expires_at) return sendMessage(res, "This confirmation link is invalid or has expired.", "/register", "Register");
    await dbRun(`INSERT INTO users (gmail, username, password_hash, public_key_pem, private_key_pem) VALUES (?, ?, ?, ?, ?)`,
      [pendingUser.gmail, pendingUser.username, pendingUser.password_hash, pendingUser.public_key_pem, pendingUser.private_key_pem]);
    await dbRun(`UPDATE pending_users SET used=1 WHERE id=?`, [pendingUser.id]);
    sendMessage(res, "Your account has been verified. Please login.", "/login", "Login");
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error during confirmation: ${err.message}`, "/register", "Register");
  }
});

app.get('/login', (req, res) => { res.sendFile(path.join(__dirname, 'views', 'login.html')); });
app.post('/login', async (req, res) => {
  const { gmail, password } = req.body;
  try {
    const user = await dbGet(`SELECT * FROM users WHERE gmail=?`, [gmail]);
    if (!user || !checkPassword(user.password_hash, password)) return sendMessage(res, "Invalid Email or Password.", "/login", "Back");
    req.session.tempUser = { id: user.id, gmail: user.gmail };
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 3 * 60 * 1000;
    if (!globalOTPStore['login']) globalOTPStore['login'] = {};
    globalOTPStore['login'][user.id] = { otp, expiresAt, used: false };
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.gmail,
      subject: 'QRLock Login OTP',
      text: `Your OTP for login is: ${otp}. It expires in 3 minutes.`
    };
    transporter.sendMail(mailOptions, (error, info) => { if (error) console.error('Login OTP email error: ', error); else console.log('Login OTP email sent: ' + info.response); });
    res.redirect('/mfa');
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error during login: ${err.message}`, "/login", "Back");
  }
});
app.get('/mfa', (req, res) => { if (!req.session.tempUser) return res.redirect('/login'); res.sendFile(path.join(__dirname, 'views', 'mfa.html')); });
app.post('/mfa', async (req, res) => {
  const { otp } = req.body;
  if (!req.session.tempUser) return res.redirect('/login');
  try {
    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.tempUser.id]);
    if (!user) return res.redirect('/login');
    const storedOTP = globalOTPStore['login'][user.id];
    if (!storedOTP || Date.now() > storedOTP.expiresAt || storedOTP.used || otp !== storedOTP.otp)
      return sendMessage(res, "Invalid or expired OTP.", "/login", "Back to Login");
    storedOTP.used = true;
    req.session.userId = user.id;
    delete req.session.tempUser;
    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error during OTP verification: ${err.message}`, "/mfa", "Back");
  }
});

app.get('/forgot', (req, res) => { res.sendFile(path.join(__dirname, 'views', 'forgot.html')); });
app.post('/forgot', async (req, res) => {
  const { gmail } = req.body;
  if (!gmail) return sendMessage(res, "Please enter your Gmail.", "/forgot", "Back");
  try {
    const user = await dbGet(`SELECT * FROM users WHERE gmail=?`, [gmail]);
    if (!user) return sendMessage(res, "If an account with that email exists, a reset link has been sent.", "/login", "Back to Login");
    const token = crypto.randomBytes(20).toString('hex');
    const expiresAt = Date.now() + 3600000;
    await dbRun(`INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)`, [user.id, token, expiresAt]);
    const resetLink = `http://${req.headers.host}/reset-password?token=${token}`;
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: gmail,
      subject: 'QRLock Password Reset',
      text: `You requested a password reset. Please click the following link to reset your password: ${resetLink}`
    };
    transporter.sendMail(mailOptions, (error, info) => { if (error) console.error('Forgot Password email error: ', error); else console.log('Forgot Password email sent: ' + info.response); });
    sendMessage(res, "If an account with that email exists, a reset link has been sent.", "/login", "Back to Login");
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error: ${err.message}`, "/forgot", "Back");
  }
});
app.get('/reset-password', async (req, res) => {
  const { token } = req.query;
  if (!token) return sendMessage(res, "Invalid or expired link.", "/login", "Back to Login");
  const tokenRecord = await dbGet(`SELECT * FROM password_reset_tokens WHERE token=? AND used=0`, [token]);
  if (!tokenRecord || Date.now() > tokenRecord.expires_at)
    return sendMessage(res, "This reset link is invalid or has expired.", "/login", "Back to Login");
  serveTemplate(res, path.join(__dirname, 'views', 'resetPassword.html'), { token });
});
app.post('/reset-password', async (req, res) => {
  const { token, newPassword, confirmPassword } = req.body;
  if (!token || !newPassword || !confirmPassword)
    return sendMessage(res, "All fields are required.", `/reset-password?token=${token}`, "Back");
  if (!isStrongPassword(newPassword))
    return sendMessage(res, "Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.", `/reset-password?token=${token}`, "Back");
  if (newPassword !== confirmPassword)
    return sendMessage(res, "Passwords do not match.", `/reset-password?token=${token}`, "Back");
  try {
    const tokenRecord = await dbGet(`SELECT * FROM password_reset_tokens WHERE token=? AND used=0`, [token]);
    if (!tokenRecord || Date.now() > tokenRecord.expires_at)
      return sendMessage(res, "This reset link is invalid or has expired.", "/login", "Back to Login");
    const newHashedPassword = hashPassword(newPassword);
    await dbRun(`UPDATE users SET password_hash=? WHERE id=?`, [newHashedPassword, tokenRecord.user_id]);
    await dbRun(`UPDATE password_reset_tokens SET used=1 WHERE id=?`, [tokenRecord.id]);
    sendMessage(res, "Password reset successful. Please login again.", "/login", "Login");
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error: ${err.message}`, `/reset-password?token=${token}`, "Back");
  }
});

app.get('/dashboard', requireLogin, async (req, res) => {
  try {
    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
    if (!user) return res.redirect('/logout');
    serveTemplate(res, path.join(__dirname, 'views', 'dashboard.html'), { username: user.username, gmail: user.gmail });
  } catch (err) {
    console.error(err);
    res.redirect('/logout');
  }
});

app.get('/account/change-username', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'changeUsername.html'));
});
app.post('/account/change-username', requireLogin, async (req, res) => {
  const { newUsername } = req.body;
  if (!newUsername) return sendMessage(res, "New username is required.", "/account/change-username", "Back");
  try {
    const existing = await dbGet(`SELECT * FROM users WHERE username=?`, [newUsername]);
    if (existing) return sendMessage(res, "Username already in use.", "/account/change-username", "Back");
    await dbRun(`UPDATE users SET username=? WHERE id=?`, [newUsername, req.session.userId]);
    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
    const mailOptions = { from: process.env.EMAIL_USER, to: user.gmail, subject: 'QRLock Username Changed', text: `Your username has been changed to ${newUsername}.` };
    transporter.sendMail(mailOptions, (error, info) => { if (error) console.error('Username change email error: ', error); else console.log('Username change email sent: ' + info.response); });
    sendMessage(res, "Username changed successfully.", "/dashboard", "Back to Dashboard");
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error: ${err.message}`, "/account/change-username", "Back");
  }
});
app.get('/account/change-password', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'changePassword.html'));
});
app.post('/account/change-password', requireLogin, async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  if (!currentPassword || !newPassword || !confirmPassword) return sendMessage(res, "All fields are required.", "/account/change-password", "Back");
  if (!isStrongPassword(newPassword)) return sendMessage(res, "Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.", "/account/change-password", "Back");
  if (newPassword !== confirmPassword) return sendMessage(res, "New passwords do not match.", "/account/change-password", "Back");
  try {
    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
    if (!user || !checkPassword(user.password_hash, currentPassword)) return sendMessage(res, "Current password is incorrect.", "/account/change-password", "Back");
    const newHashedPassword = hashPassword(newPassword);
    await dbRun(`UPDATE users SET password_hash=? WHERE id=?`, [newHashedPassword, req.session.userId]);
    const mailOptions = { from: process.env.EMAIL_USER, to: user.gmail, subject: 'QRLock Password Changed', text: 'Your password has been changed successfully.' };
    transporter.sendMail(mailOptions, (error, info) => { if (error) console.error('Password change email error: ', error); else console.log('Password change email sent: ' + info.response); });
    req.session.destroy(() => { sendMessage(res, "Password changed successfully. Please login again.", "/login", "Login"); });
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error: ${err.message}`, "/account/change-password", "Back");
  }
});
app.get('/account/delete', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'deleteAccount.html'));
});
app.post('/account/delete', requireLogin, async (req, res) => {
  const { currentPassword } = req.body;
  if (!currentPassword) return sendMessage(res, "Password is required.", "/account/delete", "Back");
  try {
    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
    if (!user || !checkPassword(user.password_hash, currentPassword)) return sendMessage(res, "Password is incorrect.", "/account/delete", "Back");
    const token = crypto.randomBytes(20).toString('hex');
    const expiresAt = Date.now() + 300000;
    await dbRun(`INSERT INTO account_deletion_tokens (user_id, token, expires_at) VALUES (?, ?, ?)`, [user.id, token, expiresAt]);
    const confirmLink = `http://${req.headers.host}/account/delete/confirm?token=${token}`;
    const mailOptions = { from: process.env.EMAIL_USER, to: user.gmail, subject: 'QRLock Account Deletion Confirmation', text: `You requested account deletion. Please confirm by clicking the following link: ${confirmLink}\nThis link expires in 5 minutes.` };
    transporter.sendMail(mailOptions, (error, info) => { if (error) console.error('Account deletion email error: ', error); else console.log('Account deletion confirmation email sent: ' + info.response); });
    sendMessage(res, "A confirmation link has been sent to your Gmail. Please click the link to delete your account.", "/dashboard", "Back to Dashboard");
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error: ${err.message}`, "/account/delete", "Back");
  }
});
app.get('/account/delete/confirm', async (req, res) => {
  const { token } = req.query;
  if (!token) return sendMessage(res, "Invalid or expired link.", "/dashboard", "Back to Dashboard");
  try {
    const tokenRecord = await dbGet(`SELECT * FROM account_deletion_tokens WHERE token=? AND used=0`, [token]);
    if (!tokenRecord || Date.now() > tokenRecord.expires_at) return sendMessage(res, "This deletion link is invalid or has expired.", "/dashboard", "Back to Dashboard");
    await dbRun(`DELETE FROM users WHERE id=?`, [tokenRecord.user_id]);
    await dbRun(`UPDATE account_deletion_tokens SET used=1 WHERE id=?`, [tokenRecord.id]);
    req.session.destroy(() => { sendMessage(res, "Your account has been deleted.", "/home", "Back to Home"); });
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error: ${err.message}`, "/dashboard", "Back to Dashboard");
  }
});

app.get('/files', requireLogin, async (req, res) => {
  try {
    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
    const files = await dbAll(`SELECT * FROM files`);
    let readyFilesHtml = "";
    files.forEach(f => {
      const recips = JSON.parse(f.recipients);
      if (globalReconstructedKey[f.file_id] && recips.includes(user.username) && f.uploader_id !== user.id) {
        readyFilesHtml += `<div class="file-item">
          <h4>${f.original_filename}</h4>
          <a href="/download/${f.file_id}" class="btn">Download</a>
        </div>`;
      }
    });
    serveTemplate(res, path.join(__dirname, 'views', 'files.html'), { fileList: readyFilesHtml || "<p>No files ready for download.</p>" });
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error: ${err.message}`, "/dashboard", "Back");
  }
});

app.get('/encrypt', requireLogin, (req, res) => { res.sendFile(path.join(__dirname, 'views', 'encrypt.html')); });
app.post('/encrypt', requireLogin, upload.single('file_to_encrypt'), async (req, res) => {
  try {
    if (!req.file) return sendMessage(res, "No file uploaded.", "/encrypt", "Back");
    let recipientsInput = req.body.recipients;
    if (!recipientsInput) return sendMessage(res, "No recipients entered.", "/encrypt", "Back");
    let recipients = recipientsInput.split(',').map(r => r.trim()).filter(r => r !== "");
    if (recipients.length === 0) return sendMessage(res, "No valid recipients entered.", "/encrypt", "Back");
    const fileData = req.file.buffer;
    const aesKey = forge.random.getBytesSync(32);
    const aesKeyBuf = Buffer.from(aesKey, 'binary');
    const { ciphertext, iv, tag } = aesEncrypt(fileData, aesKeyBuf);
    let payload;
    const file_id = Date.now().toString() + Math.floor(Math.random() * 1000).toString();
    // For single recipient
    if (recipients.length === 1) {
      const user = await dbGet(`SELECT * FROM users WHERE username=?`, [recipients[0]]);
      if (!user) return sendMessage(res, `User ${recipients[0]} not found.`, "/encrypt", "Back");
      const encryptedKey = rsaEncrypt(user.public_key_pem, aesKeyBuf);
      payload = {
        original_filename: req.file.originalname,
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        encrypted_key: encryptedKey.toString('base64'),
        threshold: 1,
        file_id: file_id
      };
    } else {
      const aesKeyHex = aesKeyBuf.toString('hex');
      const shares = splitSecret(aesKeyHex, recipients.length, recipients.length);
      let encryptedShares = [];
      for (let i = 0; i < recipients.length; i++) {
        const recipUsername = recipients[i];
        const user = await dbGet(`SELECT * FROM users WHERE username=?`, [recipUsername]);
        if (!user) return sendMessage(res, `User ${recipUsername} not found.`, "/encrypt", "Back");
        const shareStr = shares[i];
        const shareBuf = Buffer.from(shareStr, 'utf8');
        const encShareBuf = rsaEncrypt(user.public_key_pem, shareBuf);
        encryptedShares.push({ username: recipUsername, encrypted_share: encShareBuf.toString('base64') });
      }
      payload = {
        original_filename: req.file.originalname,
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        encrypted_shares: encryptedShares,
        threshold: recipients.length,
        file_id: file_id
      };
    }
    const payloadStr = JSON.stringify(payload, null, 2);
    const fillerMessage = "This QR Code contains secure encrypted data. Do not attempt to retrieve hidden info.";
    const qrBuffer = await embedPayloadInQRCodeLSB(payloadStr, fillerMessage);
    const qrFilePath = path.join(qrDir, `${file_id}.png`);
    fs.writeFileSync(qrFilePath, qrBuffer);
    await dbRun(`INSERT INTO files (uploader_id, original_filename, qr_code_path, json_payload, recipients, threshold, file_id, downloads) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.session.userId, req.file.originalname, qrFilePath, payloadStr, JSON.stringify(recipients), recipients.length, file_id, '[]']);
    serveTemplate(res, path.join(__dirname, 'views', 'encryptSuccess.html'), { file_id });
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error during encryption: ${err.message}`, "/encrypt", "Back");
  }
});

app.get('/decrypt', requireLogin, async (req, res) => {
  try {
    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
    if (!user) return res.redirect('/logout');
    const files = await dbAll(`SELECT * FROM files`);
    let fileListHtml = "";
    files.filter(f => {
      const recips = JSON.parse(f.recipients);
      return recips.includes(user.username) && f.uploader_id !== user.id;
    }).forEach(f => {
      fileListHtml += `<div class="file-item">
        <h4>${f.original_filename}</h4>
        <img src="/qrcodes/${f.file_id}.png" alt="QR Code" class="qr-image" />
        <a href="/decrypt/${f.file_id}">Decrypt</a>
      </div>`;
    });
    serveTemplate(res, path.join(__dirname, 'views', 'decrypt.html'), { fileList: fileListHtml || "<p>No files available for decryption.</p>" });
  } catch (err) {
    console.error(err);
    res.redirect('/dashboard');
  }
});

app.get('/decrypt/:file_id', requireLogin, async (req, res) => {
  try {
    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
    const file_id = req.params.file_id;
    const fileRecord = await dbGet(`SELECT * FROM files WHERE file_id=?`, [file_id]);
    if (!fileRecord) return sendMessage(res, "File not found or already decrypted.", "/dashboard", "Back");
    if (fileRecord.uploader_id === user.id) return sendMessage(res, "Not authorized to decrypt this file.", "/dashboard", "Back");
    let payloadStr;
    try {
      const imgBuffer = fs.readFileSync(fileRecord.qr_code_path);
      payloadStr = extractPayloadLSB(imgBuffer);
    } catch (err) {
      return sendMessage(res, "Failed to extract payload from QR code.", "/dashboard", "Back");
    }
    const payload = JSON.parse(payloadStr);
    if (payload.encrypted_key) {
      if (!globalOTPStore[file_id]) globalOTPStore[file_id] = {};
      let otpEntry = globalOTPStore[file_id][user.username];
      const now = Date.now();
      if (!otpEntry || now > otpEntry.expiresAt) {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = now + 3 * 60 * 1000;
        otpEntry = { otp, expiresAt, used: false };
        globalOTPStore[file_id][user.username] = otpEntry;
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: user.gmail,
          subject: 'QRLock Decryption OTP',
          text: `Your OTP for decrypting the file ${payload.original_filename} is: ${otp}. It expires in 3 minutes.`
        };
        transporter.sendMail(mailOptions, (error, info) => { if (error) console.error('Decryption OTP email error: ', error); else console.log('Decryption OTP email sent: ' + info.response); });
      }
      serveTemplate(res, path.join(__dirname, 'views', 'otpPrompt.html'), { file_id });
    } else {
      const myShareObj = payload.encrypted_shares.find(sh => sh.username === user.username);
      if (!myShareObj) return sendMessage(res, "You are not authorized for this file.", "/dashboard", "Back");
      if (!globalOTPStore[file_id]) globalOTPStore[file_id] = {};
      let otpEntry = globalOTPStore[file_id][user.username];
      const now = Date.now();
      if (!otpEntry || now > otpEntry.expiresAt) {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = now + 3 * 60 * 1000;
        otpEntry = { otp, expiresAt, used: false };
        globalOTPStore[file_id][user.username] = otpEntry;
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: user.gmail,
          subject: 'QRLock Decryption OTP',
          text: `Your OTP for decrypting the file ${payload.original_filename} is: ${otp}. It expires in 3 minutes.`
        };
        transporter.sendMail(mailOptions, (error, info) => { if (error) console.error('Decryption OTP email error: ', error); else console.log('Decryption OTP email sent: ' + info.response); });
      }
      serveTemplate(res, path.join(__dirname, 'views', 'otpPrompt.html'), { file_id });
    }
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error: ${err.message}`, "/dashboard", "Back");
  }
});

app.post('/decrypt/:file_id', requireLogin, async (req, res) => {
  try {
    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
    const file_id = req.params.file_id;
    const enteredOTP = req.body.otp;
    const fileRecord = await dbGet(`SELECT * FROM files WHERE file_id=?`, [file_id]);
    if (!fileRecord) return sendMessage(res, "File not found or already decrypted.", "/dashboard", "Back");
    if (fileRecord.uploader_id === user.id) return sendMessage(res, "Not authorized to decrypt this file.", "/dashboard", "Back");
    let payloadStr;
    try {
      const imgBuffer = fs.readFileSync(fileRecord.qr_code_path);
      payloadStr = extractPayloadLSB(imgBuffer);
    } catch (err) {
      return sendMessage(res, "Failed to extract payload from QR code.", "/dashboard", "Back");
    }
    const payload = JSON.parse(payloadStr);
    let aesKeyBuf;
    if (payload.encrypted_key) {
      aesKeyBuf = rsaDecrypt(user.private_key_pem, Buffer.from(payload.encrypted_key, 'base64'));
      if (!globalOTPStore[file_id] || !globalOTPStore[file_id][user.username])
        return sendMessage(res, "OTP not found. Please try again.", `/decrypt/${file_id}`, "Retry");
      const otpEntry = globalOTPStore[file_id][user.username];
      if (otpEntry.used) return sendMessage(res, "This OTP has already been used.", "/dashboard", "Back");
      if (Date.now() > otpEntry.expiresAt) { delete globalOTPStore[file_id][user.username]; return sendMessage(res, "OTP expired.", `/decrypt/${file_id}`, "Request new OTP"); }
      if (enteredOTP !== otpEntry.otp) return sendMessage(res, "Invalid OTP.", `/decrypt/${file_id}`, "Try again");
      otpEntry.used = true;
      delete globalOTPStore[file_id][user.username];
      if (!globalReconstructedKey[file_id]) globalReconstructedKey[file_id] = aesKeyBuf;
      return sendMessage(res, "File is now ready for download. Please go to the Files page.", "/files", "Files");
    } else {
      const myShareObj = payload.encrypted_shares.find(sh => sh.username === user.username);
      if (!myShareObj) return sendMessage(res, "You are not authorized for this file.", "/dashboard", "Back");
      if (!globalOTPStore[file_id] || !globalOTPStore[file_id][user.username])
        return sendMessage(res, "OTP not found. Please try again.", `/decrypt/${file_id}`, "Retry");
      const otpEntry = globalOTPStore[file_id][user.username];
      if (otpEntry.used) return sendMessage(res, "This OTP has already been used.", "/dashboard", "Back");
      if (Date.now() > otpEntry.expiresAt) { delete globalOTPStore[file_id][user.username]; return sendMessage(res, "OTP expired.", `/decrypt/${file_id}`, "Request new OTP"); }
      if (enteredOTP !== otpEntry.otp) return sendMessage(res, "Invalid OTP.", `/decrypt/${file_id}`, "Try again");
      otpEntry.used = true;
      delete globalOTPStore[file_id][user.username];
      const shareBuf = Buffer.from(myShareObj.encrypted_share, 'base64');
      const decShareBuf = rsaDecrypt(user.private_key_pem, shareBuf);
      if (!globalDecryptionPool[file_id]) globalDecryptionPool[file_id] = {};
      globalDecryptionPool[file_id][user.username] = decShareBuf.toString('utf8');
      const shares = Object.values(globalDecryptionPool[file_id]);
      if (shares.length >= JSON.parse(fileRecord.recipients).length) {
        const combinedHex = recoverSecret(shares.slice(0, shares.length));
        aesKeyBuf = Buffer.from(combinedHex, 'hex');
        globalReconstructedKey[file_id] = aesKeyBuf;
        return sendMessage(res, "File is now ready for download. Please go to the Files page.", "/files", "Files");
      } else {
        return sendMessage(res, `Your share is accepted. We have ${shares.length} of ${JSON.parse(fileRecord.recipients).length} required shares. (Ask other authorized users to click "Decrypt" on this file.)`, "/dashboard", "Back");
      }
    }
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error in decryption: ${err.message}`, "/dashboard", "Back");
  }
});

app.get('/download/:file_id', requireLogin, async (req, res) => {
  try {
    const user = await dbGet(`SELECT * FROM users WHERE id=?`, [req.session.userId]);
    const file_id = req.params.file_id;
    const fileRecord = await dbGet(`SELECT * FROM files WHERE file_id=?`, [file_id]);
    if (!fileRecord) return sendMessage(res, "File not found.", "/dashboard", "Back");
    if (fileRecord.uploader_id === user.id)
      return sendMessage(res, "Not authorized to download this file.", "/dashboard", "Back");
    let payloadStr = extractPayloadLSB(fs.readFileSync(fileRecord.qr_code_path));
    const payload = JSON.parse(payloadStr);
    let aesKeyBuf;
    if (payload.encrypted_key) {
      aesKeyBuf = rsaDecrypt(user.private_key_pem, Buffer.from(payload.encrypted_key, 'base64'));
    } else if (globalReconstructedKey[file_id]) {
      aesKeyBuf = globalReconstructedKey[file_id];
    } else {
      return sendMessage(res, "File not ready for download yet.", "/dashboard", "Back");
    }
    const ivBuf = Buffer.from(payload.iv, 'base64');
    const tagBuf = Buffer.from(payload.tag, 'base64');
    const ciphertextBuf = Buffer.from(payload.ciphertext, 'base64');
    const plainBuf = aesDecrypt(ciphertextBuf, aesKeyBuf, ivBuf, tagBuf);
    let downloads = [];
    try { downloads = JSON.parse(fileRecord.downloads || '[]'); } catch (e) { downloads = []; }
    if (!downloads.includes(user.username)) {
      downloads.push(user.username);
      await dbRun("UPDATE files SET downloads=? WHERE file_id=?", [JSON.stringify(downloads), file_id]);
    }
    const recipients = JSON.parse(fileRecord.recipients);
    if (downloads.length >= recipients.length) {
      await dbRun("DELETE FROM files WHERE file_id=?", [file_id]);
      fs.unlinkSync(fileRecord.qr_code_path);
    }
    res.setHeader('Content-Disposition', `attachment; filename="DECRYPTED_${payload.original_filename}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    return res.send(plainBuf);
  } catch (err) {
    console.error(err);
    sendMessage(res, `Error during download: ${err.message}`, "/dashboard", "Back");
  }
});

app.get('/logout', (req, res) => { req.session.destroy(() => { res.redirect('/home'); }); });

app.listen(PORT, () => { console.log(`Server running on http://localhost:${PORT}`); });
