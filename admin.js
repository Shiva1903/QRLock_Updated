const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
require('dotenv').config();

const router = express.Router();

// Ensure body parsing for this router
router.use(express.urlencoded({ extended: false }));
router.use(express.json());

const dbPath = path.join(__dirname, "database.sqlite");
const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) console.error("Error opening database:", err.message);
  else console.log("Connected to SQLite database at:", dbPath);
});

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => { if (err) reject(err); else resolve(row); });
  });
}
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this.lastID);
    });
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => { if (err) reject(err); else resolve(rows); });
  });
}

function hashPassword(password) {
  const salt = bcrypt.genSaltSync(10);
  return bcrypt.hashSync(password, salt);
}
function checkPassword(storedHash, candidate) {
  return bcrypt.compareSync(candidate, storedHash);
}

const globalOTPStore = {};

// Templating helper: simply replace placeholders in file
function serveTemplate(res, templatePath, replacements) {
  fs.readFile(templatePath, "utf8", (err, data) => {
    if (err) return res.status(500).send("Error loading template.");
    let output = data;
    for (let key in replacements) {
      const token = new RegExp(`{{\\s*${key}\\s*}}`, "g");
      output = output.replace(token, replacements[key]);
    }
    res.send(output);
  });
}

function serveFileWithError(res, filePath, errorMessage, message) {
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) return res.status(500).send("Error loading template.");
    let output = data;
    output = output.replace(/{{\s*errorMessage\s*}}/g, errorMessage || "");
    output = output.replace(/{{\s*message\s*}}/g, message || "");
    res.send(output);
  });
}

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// ------------------ Admin Authentication ------------------ //

// GET /login – Admin login page
router.get("/login", (req, res) => {
  const errorMessage = req.query.error || "";
  const filePath = path.join(__dirname, "views", "adminLogin.html");
  serveFileWithError(res, filePath, errorMessage, "");
});

// POST /login – Process admin login credentials
router.post("/login", async (req, res) => {
  try {
    const { gmail, password } = req.body;
    const adminEmail = process.env.ADMIN_EMAIL || "shivasomucsc@gmail.com";
    if (gmail !== adminEmail) {
      return res.redirect("/system-core-access-106014491553/login?error=Incorrect+gmail+id+or+password");
    }
    const admin = await dbGet("SELECT * FROM users WHERE gmail=?", [adminEmail]);
    if (!admin || !checkPassword(admin.password_hash, password)) {
      return res.redirect("/system-core-access-106014491553/login?error=Incorrect+gmail+id+or+password");
    }
    req.session.tempAdmin = { id: admin.id, gmail: admin.gmail };
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 3 * 60 * 1000;
    if (!globalOTPStore["admin"]) globalOTPStore["admin"] = {};
    globalOTPStore["admin"][admin.id] = { otp, expiresAt, used: false };
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: admin.gmail,
      subject: "QRLock Admin Login OTP",
      text: `Your OTP for admin login is: ${otp}. It expires in 3 minutes.`
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) console.error("Admin OTP email error:", error);
      else console.log("Admin OTP email sent:", info.response);
    });
    res.redirect("/system-core-access-106014491553/mfa");
  } catch (err) {
    console.error(err);
    res.redirect("/system-core-access-106014491553/login?error=" + encodeURIComponent("Error during admin login: " + err.message));
  }
});

// GET /mfa – Admin OTP entry page
router.get("/mfa", (req, res) => {
  if (!req.session.tempAdmin) return res.redirect("/system-core-access-106014491553/login");
  res.sendFile(path.join(__dirname, "views", "adminMfa.html"));
});

// POST /mfa – Process admin OTP
router.post("/mfa", async (req, res) => {
  try {
    const { otp } = req.body;
    if (!req.session.tempAdmin) return res.redirect("/system-core-access-106014491553/login");
    const admin = await dbGet("SELECT * FROM users WHERE id=?", [req.session.tempAdmin.id]);
    if (!admin) return res.redirect("/system-core-access-106014491553/login");
    const storedOTP = globalOTPStore["admin"][admin.id];
    if (!storedOTP || Date.now() > storedOTP.expiresAt || storedOTP.used || otp !== storedOTP.otp) {
      return res.redirect("/system-core-access-106014491553/login?error=Incorrect+gmail+id+or+password");
    }
    storedOTP.used = true;
    req.session.admin = true;
    req.session.userId = admin.id;
    delete req.session.tempAdmin;
    res.redirect("/system-core-access-106014491553/dashboard");
  } catch (err) {
    console.error(err);
    res.redirect("/system-core-access-106014491553/login?error=" + encodeURIComponent("Error during admin OTP verification: " + err.message));
  }
});

// ------------------ Admin Dashboard & Change Password ------------------ //

// GET /dashboard – Admin dashboard
router.get("/dashboard", async (req, res) => {
  try {
    if (!req.session.admin) return res.redirect("/system-core-access-106014491553/login");
    const admin = await dbGet("SELECT * FROM users WHERE id=?", [req.session.userId]);
    if (!admin) return res.redirect("/system-core-access-106014491553/login");
    const filePath = path.join(__dirname, "views", "adminDashboard.html");
    serveTemplate(res, filePath, { adminLabel: "Admin", gmail: admin.gmail });
  } catch (err) {
    console.error(err);
    res.redirect("/system-core-access-106014491553/login");
  }
});

// GET /change-password – Admin change password page
router.get("/change-password", (req, res) => {
  if (!req.session.admin) return res.redirect("/system-core-access-106014491553/login");
  res.sendFile(path.join(__dirname, "views", "adminChangePassword.html"));
});

// POST /change-password – Process admin change password
router.post("/change-password", async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.send("All fields are required. <a href='/system-core-access-106014491553/change-password'>Back</a>");
    }
    const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
    if (!strongRegex.test(newPassword)) {
      return res.send("Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character. <a href='/system-core-access-106014491553/change-password'>Back</a>");
    }
    if (newPassword !== confirmPassword) {
      return res.send("New passwords do not match. <a href='/system-core-access-106014491553/change-password'>Back</a>");
    }
    const admin = await dbGet("SELECT * FROM users WHERE id=?", [req.session.userId]);
    if (!admin || !checkPassword(admin.password_hash, currentPassword)) {
      return res.send("Current password is incorrect. <a href='/system-core-access-106014491553/change-password'>Back</a>");
    }
    const newHashedPassword = hashPassword(newPassword);
    await dbRun("UPDATE users SET password_hash=? WHERE id=?", [newHashedPassword, admin.id]);
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: admin.gmail,
      subject: "QRLock Admin Password Changed",
      text: "Your admin password has been changed successfully.",
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) console.error("Admin password change email error:", error);
      else console.log("Admin password change email sent:", info.response);
    });
    req.session.destroy(() => {
      res.send("Password changed successfully. Please <a href='/system-core-access-106014491553/login'>login</a> again as admin.");
    });
  } catch (err) {
    console.error(err);
    res.send("Error: " + err.message + " <a href='/system-core-access-106014491553/change-password'>Back</a>");
  }
});

// ------------------ Admin Users Management ------------------ //

// GET /users – List all non-admin users with search
router.get("/users", async (req, res) => {
  try {
    if (!req.session.admin) return res.redirect("/system-core-access-106014491553/login");
    const adminId = req.session.userId;
    const searchQuery = req.query.search ? req.query.search.trim() : "";
    let queryStr, params;
    if (searchQuery) {
      queryStr = "SELECT * FROM users WHERE (gmail LIKE ? OR username LIKE ?) AND id <> ?";
      params = [`%${searchQuery}%`, `%${searchQuery}%`, adminId];
    } else {
      queryStr = "SELECT * FROM users WHERE id <> ?";
      params = [adminId];
    }
    const rows = await dbAll(queryStr, params);
    let tableRows = "";
    rows.forEach((row, index) => {
      tableRows += `<tr>
        <td>${index + 1}</td>
        <td>${row.gmail}</td>
        <td>${row.username}</td>
        <td><a class="action-btn" href="/system-core-access-106014491553/users/delete?userId=${row.id}&gmail=${encodeURIComponent(row.gmail)}">Delete</a></td>
      </tr>`;
    });
    serveTemplate(res, path.join(__dirname, "views", "adminUsers.html"), { tableRows, searchQuery });
  } catch (err) {
    console.error(err);
    res.send("Error retrieving users: " + err.message);
  }
});

// GET /users/delete – Show confirmation for deletion
router.get("/users/delete", async (req, res) => {
  if (!req.session.admin) return res.redirect("/system-core-access-106014491553/login");
  const { userId, gmail } = req.query;
  serveTemplate(res, path.join(__dirname, "views", "adminUserDeleteConfirm.html"), { userId, gmail });
});

// POST /users/delete – Process deletion confirmation: generate OTP and redirect to OTP entry form
router.post("/users/delete", async (req, res) => {
  try {
    if (!req.session.admin) return res.redirect("/system-core-access-106014491553/login");
    const { userId, gmail } = req.body;
    const admin = await dbGet("SELECT * FROM users WHERE id=?", [req.session.userId]);
    if (!admin) return res.redirect("/system-core-access-106014491553/login");
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 3 * 60 * 1000;
    if (!globalOTPStore["delete"]) globalOTPStore["delete"] = {};
    globalOTPStore["delete"][admin.id] = { otp, expiresAt, used: false, userId };
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: admin.gmail,
      subject: "QRLock Admin Delete User OTP",
      text: `Your OTP for deleting the user with gmail "${gmail}" is: ${otp}. It expires in 3 minutes.`,
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Admin delete OTP email error:", error);
        return res.send("Failed to send OTP email. <a href='/system-core-access-106014491553/users'>Back to Users</a>");
      } else {
        console.log("Admin delete OTP email sent:", info.response);
        return res.redirect(`/system-core-access-106014491553/users/delete/otp?userId=${userId}&gmail=${encodeURIComponent(gmail)}`);
      }
    });
  } catch (err) {
    console.error(err);
    res.send("Error processing deletion: " + err.message);
  }
});

// GET /users/delete/otp – Display OTP entry form for deletion
router.get("/users/delete/otp", (req, res) => {
  if (!req.session.admin) return res.redirect("/system-core-access-106014491553/login");
  const { userId, gmail } = req.query;
  serveTemplate(res, path.join(__dirname, "views", "adminUserDeleteOtp.html"), { userId, gmail });
});

// POST /users/delete/otp – Verify OTP and delete user
router.post("/users/delete/otp", async (req, res) => {
  if (!req.session.admin) return res.redirect("/system-core-access-106014491553/login");
  const { userId, gmail, otp } = req.body;
  const admin = await dbGet("SELECT * FROM users WHERE id=?", [req.session.userId]);
  if (!admin) return res.redirect("/system-core-access-106014491553/login");
  if (!globalOTPStore["delete"] || !globalOTPStore["delete"][admin.id]) {
    return res.send("OTP not found. <a href='/system-core-access-106014491553/users'>Back to Users</a>");
  }
  const otpRecord = globalOTPStore["delete"][admin.id];
  if (Date.now() > otpRecord.expiresAt || otpRecord.used || otp !== otpRecord.otp) {
    return serveTemplate(res, path.join(__dirname, "views", "adminOtpError.html"), {
      errorMessage: "Incorrect OTP",
      redirectLink: "/system-core-access-106014491553/users",
      buttonText: "Back to Users",
    });
  }
  otpRecord.used = true;
  await dbRun("DELETE FROM users WHERE id=?", [userId]);
  await dbRun("DELETE FROM pending_users WHERE gmail=?", [gmail]);
  res.redirect("/system-core-access-106014491553/users");
});

// ------------------ Admin Forgot/Reset Password ------------------ //

// GET /forgot – Admin forgot password page
router.get("/forgot", (req, res) => {
  const errorMessage = req.query.error || "";
  const message = req.query.message || "";
  const filePath = path.join(__dirname, "views", "adminForgot.html");
  serveFileWithError(res, filePath, errorMessage, message);
});

// POST /forgot – Process admin forgot password
router.post("/forgot", async (req, res) => {
  try {
    const { gmail } = req.body;
    const adminEmail = process.env.ADMIN_EMAIL || "shivasomucsc@gmail.com";
    if (gmail !== adminEmail) {
      return res.redirect("/system-core-access-106014491553/forgot?error=Email+not+found");
    }
    const admin = await dbGet("SELECT * FROM users WHERE gmail=?", [adminEmail]);
    if (!admin) {
      return res.redirect("/system-core-access-106014491553/forgot?error=Email+not+found");
    }
    const token = crypto.randomBytes(20).toString("hex");
    const expiresAt = Date.now() + 3600000;
    await dbRun("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)", [admin.id, token, expiresAt]);
    const resetLink = `http://${req.headers.host}/system-core-access-106014491553/reset-password?token=${token}`;
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: adminEmail,
      subject: "QRLock Admin Password Reset",
      text: `You requested a password reset. Please click the following link to reset your password: ${resetLink}`,
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) console.error("Admin forgot password email error:", error);
      else console.log("Admin forgot password email sent:", info.response);
    });
    res.redirect("/system-core-access-106014491553/forgot?message=If+an+account+with+that+email+exists,+a+reset+link+has+been+sent");
  } catch (err) {
    console.error(err);
    res.redirect("/system-core-access-106014491553/forgot?error=" + encodeURIComponent("Error: " + err.message));
  }
});

// GET /reset-password – Admin reset password page
router.get("/reset-password", async (req, res) => {
  const { token } = req.query;
  if (!token) return res.send("Invalid or expired link.");
  const tokenRecord = await dbGet("SELECT * FROM password_reset_tokens WHERE token=? AND used=0", [token]);
  if (!tokenRecord || Date.now() > tokenRecord.expires_at) {
    return res.send("This reset link is invalid or has expired.");
  }
  serveTemplate(res, path.join(__dirname, "views", "adminResetPassword.html"), { token });
});

// POST /reset-password – Process admin reset password
router.post("/reset-password", async (req, res) => {
  try {
    const { token, newPassword, confirmPassword } = req.body;
    if (!token || !newPassword || !confirmPassword) {
      return res.send("All fields are required.");
    }
    if (newPassword !== confirmPassword) {
      return res.send("Passwords do not match.");
    }
    const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
    if (!strongRegex.test(newPassword)) {
      return res.send("Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.");
    }
    const tokenRecord = await dbGet("SELECT * FROM password_reset_tokens WHERE token=? AND used=0", [token]);
    if (!tokenRecord || Date.now() > tokenRecord.expires_at) {
      return res.send("This reset link is invalid or has expired.");
    }
    const newHashedPassword = bcrypt.hashSync(newPassword, bcrypt.genSaltSync(10));
    await dbRun("UPDATE users SET password_hash=? WHERE id=?", [newHashedPassword, tokenRecord.user_id]);
    await dbRun("UPDATE password_reset_tokens SET used=1 WHERE id=?", [tokenRecord.id]);
    res.send("Password reset successful. Please <a href='/system-core-access-106014491553/login'>login</a> as admin.");
  } catch (err) {
    console.error(err);
    res.send("Error during password reset: " + err.message);
  }
});

// ------------------ Admin Logout ------------------ //

router.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/system-core-access-106014491553/login");
  });
});

// Redirect base endpoint to /login
router.get("/", (req, res) => {
  res.redirect("/system-core-access-106014491553/login");
});

module.exports = router;
