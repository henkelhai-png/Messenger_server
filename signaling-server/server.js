const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const WebSocket = require("ws");

const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 3001);
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify({ users: [] }, null, 2));

const clients = new Map();
const sessions = new Map();

function readUsers() {
  return JSON.parse(fs.readFileSync(USERS_FILE, "utf8")).users || [];
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify({ users }, null, 2));
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function verifyPassword(password, user) {
  const { hash } = hashPassword(password, user.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(user.passwordHash, "hex"));
}

function createToken(username) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, username);
  return token;
}

function send(ws, payload) {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function broadcastUsers() {
  const users = Array.from(clients.keys());
  for (const ws of clients.values()) {
    send(ws, { type: "users:list", users });
  }
}

function registerConnection(ws, username) {
  if (clients.has(username) && clients.get(username) !== ws) {
    send(ws, { type: "auth:error", message: "Этот пользователь уже онлайн" });
    return false;
  }

  ws.username = username;
  clients.set(username, ws);
  broadcastUsers();
  return true;
}

function requireAuth(ws) {
  if (ws.username) return true;
  send(ws, { type: "auth:required", message: "Сначала выполните вход" });
  return false;
}

function forwardToUser(from, to, payload) {
  const target = clients.get(to);
  if (!target) {
    send(from, { type: "error", message: "Пользователь не в сети" });
    return;
  }

  send(target, { ...payload, from: from.username });
}

const wss = new WebSocket.Server({ host: HOST, port: PORT }, () => {
  console.log(`Signaling server started on ws://${HOST}:${PORT}`);
});

wss.on("connection", (ws) => {
  ws.on("message", (rawMessage) => {
    let data;
    try {
      data = JSON.parse(rawMessage.toString());
    } catch {
      send(ws, { type: "error", message: "Некорректный JSON" });
      return;
    }

    if (data.type === "auth:register") {
      const username = String(data.username || "").trim();
      const password = String(data.password || "");
      const users = readUsers();

      if (username.length < 3 || password.length < 4) {
        send(ws, { type: "auth:error", message: "Логин или пароль слишком короткий" });
        return;
      }

      if (users.some((user) => user.username.toLowerCase() === username.toLowerCase())) {
        send(ws, { type: "auth:error", message: "Пользователь с таким логином уже зарегистрирован" });
        return;
      }

      const { salt, hash } = hashPassword(password);
      users.push({
        id: crypto.randomUUID(),
        username,
        salt,
        passwordHash: hash,
        createdAt: new Date().toISOString(),
      });
      writeUsers(users);

      if (!registerConnection(ws, username)) return;
      const token = createToken(username);
      send(ws, { type: "auth:success", username, token, message: "Регистрация выполнена" });
      return;
    }

    if (data.type === "auth:login") {
      const username = String(data.username || "").trim();
      const password = String(data.password || "");
      const user = readUsers().find((item) => item.username.toLowerCase() === username.toLowerCase());

      if (!user || !verifyPassword(password, user)) {
        send(ws, { type: "auth:error", message: "Неверный логин или пароль" });
        return;
      }

      if (!registerConnection(ws, user.username)) return;
      const token = createToken(user.username);
      send(ws, { type: "auth:success", username: user.username, token, message: "Вход выполнен" });
      return;
    }

    if (data.type === "auth:token") {
      const username = sessions.get(data.token);
      if (!username) {
        send(ws, { type: "auth:error", message: "Сессия истекла. Войдите заново" });
        return;
      }

      if (!registerConnection(ws, username)) return;
      send(ws, { type: "auth:success", username, token: data.token, message: "Переподключение выполнено" });
      return;
    }

    if (data.type === "auth:logout") {
      ws.close();
      return;
    }

    if (!requireAuth(ws)) return;

    if (data.type === "chat:request") {
      forwardToUser(ws, data.to, { type: "chat:incoming-request" });
      send(ws, { type: "chat:request-sent", to: data.to });
      return;
    }

    if (data.type === "chat:accept") {
      forwardToUser(ws, data.to, { type: "chat:accepted" });
      return;
    }

    if (data.type === "webrtc:offer") {
      forwardToUser(ws, data.to, { type: "webrtc:offer", offer: data.offer });
      return;
    }

    if (data.type === "webrtc:answer") {
      forwardToUser(ws, data.to, { type: "webrtc:answer", answer: data.answer });
      return;
    }

    if (data.type === "webrtc:ice-candidate") {
      forwardToUser(ws, data.to, { type: "webrtc:ice-candidate", candidate: data.candidate });
      return;
    }

    send(ws, { type: "error", message: "Неизвестный тип сообщения" });
  });

  ws.on("close", () => {
    if (ws.username && clients.get(ws.username) === ws) {
      clients.delete(ws.username);
      broadcastUsers();
    }
  });
});
