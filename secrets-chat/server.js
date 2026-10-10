const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB || "secrets";
const SESSION_SECRET = process.env.SESSION_SECRET;
const production = process.env.NODE_ENV === "production";

if (!MONGODB_URI) throw new Error("Missing MONGODB_URI environment variable.");
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must be at least 32 characters.");
}

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'"],
    objectSrc: ["'none'"]
  }}
}));
app.use(express.json({ limit: "20kb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 20,
  standardHeaders: true, legacyHeaders: false
});
const messageLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 90,
  standardHeaders: true, legacyHeaders: false
});

let users, messages;

app.use(session({
  name: "secrets.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: MONGODB_URI,
    dbName: DB_NAME,
    collectionName: "sessions",
    ttl: 14 * 24 * 60 * 60
  }),
  cookie: {
    httpOnly: true,
    secure: production,
    sameSite: "lax",
    maxAge: 14 * 24 * 60 * 60 * 1000
  }
}));

const validUsername = s => typeof s === "string" && /^[A-Za-z0-9_]{3,24}$/.test(s.trim());
const validPassword = s => typeof s === "string" && s.length >= 12 && s.length <= 200;
const currentId = req => new ObjectId(req.session.userId);

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Please log in again." });
  next();
}
function requireCsrf(req, res, next) {
  const token = req.get("X-CSRF-Token") || "";
  const expected = req.session.csrf || "";
  if (!token || token.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) {
    return res.status(403).json({ error: "Security token expired. Refresh and log in again." });
  }
  next();
}
function newCsrf(req) {
  req.session.csrf = crypto.randomBytes(32).toString("hex");
  return req.session.csrf;
}
function userForClient(user) {
  return {
    username: user.username,
    publicKey: user.publicKey || null,
    online: !!user.lastSeenAt && Date.now() - user.lastSeenAt < 30000
  };
}
function validPublicKey(text) {
  try {
    const jwk = JSON.parse(text);
    return jwk && jwk.kty === "RSA" && typeof jwk.n === "string" &&
      typeof jwk.e === "string" && jwk.n.length < 2000 && jwk.e.length < 20;
  } catch { return false; }
}
function validPayload(body) {
  if (!body || !["ciphertext", "iv", "wrappedRecipientKey", "wrappedSenderKey"]
      .every(key => typeof body[key] === "string" && body[key].length > 0)) return false;
  return body.ciphertext.length <= 30000 && body.iv.length <= 100 &&
    body.wrappedRecipientKey.length <= 2000 && body.wrappedSenderKey.length <= 2000;
}

app.post("/api/register", authLimiter, async (req, res, next) => {
  try {
    const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
    const password = req.body.password;
    if (!validUsername(username)) return res.status(400).json({
      error: "Username must be 3–24 letters, numbers, or underscores."
    });
    if (!validPassword(password)) return res.status(400).json({
      error: "Password must be 12–200 characters."
    });

    const user = {
      username,
      usernameLower: username.toLowerCase(),
      passwordHash: await bcrypt.hash(password, 12),
      publicKey: null,
      createdAt: Date.now(),
      lastSeenAt: Date.now()
    };
    await users.insertOne(user);
    req.session.userId = user._id.toString();
    req.session.username = user.username;
    const csrf = newCsrf(req);
    req.session.save(err => {
      if (err) return next(err);
      res.status(201).json({ username: user.username, csrf });
    });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ error: "That username is already taken." });
    next(err);
  }
});

app.post("/api/login", authLimiter, async (req, res, next) => {
  try {
    const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
    const password = req.body.password;
    if (!validUsername(username) || typeof password !== "string") {
      return res.status(400).json({ error: "Enter a valid username and password." });
    }
    const user = await users.findOne({ usernameLower: username.toLowerCase() });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: "Incorrect username or password." });
    }
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.userId = user._id.toString();
      req.session.username = user.username;
      const csrf = newCsrf(req);
      req.session.save(saveErr => {
        if (saveErr) return next(saveErr);
        res.json({ username: user.username, csrf });
      });
    });
  } catch (err) { next(err); }
});

app.get("/api/me", async (req, res, next) => {
  try {
    if (!req.session.userId) return res.json({ loggedIn: false });
    const user = await users.findOne({ _id: currentId(req) });
    if (!user) return req.session.destroy(() => res.json({ loggedIn: false }));
    res.json({ loggedIn: true, username: user.username, csrf: req.session.csrf || newCsrf(req) });
  } catch (err) { next(err); }
});

app.post("/api/logout", requireLogin, requireCsrf, (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("secrets.sid", { httpOnly: true, secure: production, sameSite: "lax" });
    res.json({ ok: true });
  });
});

app.post("/api/key", requireLogin, requireCsrf, async (req, res, next) => {
  try {
    if (typeof req.body.publicKey !== "string" ||
        req.body.publicKey.length > 5000 || !validPublicKey(req.body.publicKey)) {
      return res.status(400).json({ error: "Invalid public key." });
    }
    await users.updateOne({ _id: currentId(req) }, {
      $set: { publicKey: req.body.publicKey, lastSeenAt: Date.now() }
    });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

app.post("/api/heartbeat", requireLogin, requireCsrf, async (req, res, next) => {
  try {
    await users.updateOne({ _id: currentId(req) }, { $set: { lastSeenAt: Date.now() } });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

app.get("/api/users", requireLogin, async (req, res, next) => {
  try {
    const list = await users.find({ _id: { $ne: currentId(req) } }, {
      projection: { username: 1, publicKey: 1, lastSeenAt: 1 }
    }).sort({ usernameLower: 1 }).limit(500).toArray();
    res.json({ users: list.map(userForClient) });
  } catch (err) { next(err); }
});

app.post("/api/messages", requireLogin, requireCsrf, messageLimiter, async (req, res, next) => {
  try {
    const recipientName = typeof req.body.recipient === "string" ? req.body.recipient.trim() : "";
    if (!validUsername(recipientName) || !validPayload(req.body)) {
      return res.status(400).json({ error: "Invalid recipient or encrypted message." });
    }
    const sender = await users.findOne({ _id: currentId(req) });
    const recipient = await users.findOne({ usernameLower: recipientName.toLowerCase() });
    if (!sender || !recipient) return res.status(404).json({ error: "Recipient account not found." });
    if (sender._id.equals(recipient._id)) return res.status(400).json({ error: "You cannot message yourself." });

    const doc = {
      senderId: sender._id,
      recipientId: recipient._id,
      sender: sender.username,
      recipient: recipient.username,
      ciphertext: req.body.ciphertext,
      iv: req.body.iv,
      wrappedRecipientKey: req.body.wrappedRecipientKey,
      wrappedSenderKey: req.body.wrappedSenderKey,
      createdAt: Math.floor(Date.now() / 1000)
    };
    const inserted = await messages.insertOne(doc);
    res.status(201).json({ ok: true, id: inserted.insertedId.toString() });
  } catch (err) { next(err); }
});

app.get("/api/messages/:username", requireLogin, async (req, res, next) => {
  try {
    const peerName = req.params.username;
    if (!validUsername(peerName)) return res.status(400).json({ error: "Invalid username." });
    const me = currentId(req);
    const peer = await users.findOne({ usernameLower: peerName.toLowerCase() });
    if (!peer) return res.status(404).json({ error: "User not found." });

    const docs = await messages.find({
      $or: [
        { senderId: me, recipientId: peer._id },
        { senderId: peer._id, recipientId: me }
      ]
    }).sort({ createdAt: 1, _id: 1 }).limit(1000).toArray();

    res.json({ messages: docs.map(m => ({
      sender: m.sender,
      recipient: m.recipient,
      ciphertext: m.ciphertext,
      iv: m.iv,
      wrappedRecipientKey: m.wrappedRecipientKey,
      wrappedSenderKey: m.wrappedSenderKey,
      createdAt: m.createdAt
    })) });
  } catch (err) { next(err); }
});

app.get("/health", (req, res) => res.json({ ok: true, service: "secrets-chat-server" }));
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.use((err, req, res, next) => {
  console.error("Request failed:", err && err.message ? err.message : err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Server error. Check service logs." });
});

async function start() {
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const db = client.db(DB_NAME);
  users = db.collection("users");
  messages = db.collection("messages");
  await users.createIndex({ usernameLower: 1 }, { unique: true });
  await messages.createIndex({ senderId: 1, recipientId: 1, createdAt: 1 });
  await messages.createIndex({ recipientId: 1, senderId: 1, createdAt: 1 });
  app.listen(PORT, "0.0.0.0", () => console.log(`Secrets is listening on port ${PORT}`));
}
start().catch(err => {
  console.error("Could not start Secrets:", err);
  process.exit(1);
});
