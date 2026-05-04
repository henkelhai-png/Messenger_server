const WebSocket = require("ws");
const fs = require("fs");

const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || "0.0.0.0";

// Запуск WebSocket-сервера
const wss = new WebSocket.Server({ port: PORT, host: HOST });

console.log(`Signaling server started on ${HOST}:${PORT}`);

let users = {};

// Загружаем пользователей из файла
function loadUsers() {
  if (fs.existsSync("data/users.json")) {
    const data = fs.readFileSync("data/users.json");
    users = JSON.parse(data);
  }
}

// Сохраняем пользователей в файл
function saveUsers() {
  fs.writeFileSync("data/users.json", JSON.stringify(users, null, 2));
}

// Обработка WebSocket-соединений
wss.on("connection", (ws) => {
  console.log("New client connected");

  // При получении сообщения
  ws.on("message", (message) => {
    const data = JSON.parse(message);
    console.log("Received message:", data);

    switch (data.type) {
      case "auth:register":
        handleRegister(ws, data);
        break;

      case "auth:login":
        handleLogin(ws, data);
        break;

      case "auth:token":
        handleToken(ws, data);
        break;

      case "auth:logout":
        handleLogout(ws, data);
        break;

      default:
        console.log("Unknown message type:", data.type);
    }
  });

  // Обработка закрытия соединения
  ws.on("close", () => {
    console.log("Client disconnected");
  });
});

// Регистрация нового пользователя
function handleRegister(ws, data) {
  if (users[data.username]) {
    ws.send(JSON.stringify({ type: "auth:register", success: false, message: "Username already taken" }));
  } else {
    const passwordHash = data.password;  // Просто для простоты, можно добавить хеширование с bcrypt
    users[data.username] = { password: passwordHash };
    saveUsers();
    ws.send(JSON.stringify({ type: "auth:register", success: true, message: "Registration successful" }));
  }
}

// Вход для зарегистрированного пользователя
function handleLogin(ws, data) {
  const user = users[data.username];
  if (user && user.password === data.password) {
    ws.send(JSON.stringify({ type: "auth:login", success: true, message: "Login successful" }));
  } else {
    ws.send(JSON.stringify({ type: "auth:login", success: false, message: "Invalid username or password" }));
  }
}

// Проверка токена (для теста, можно заменить на JWT)
function handleToken(ws, data) {
  const user = users[data.username];
  if (user) {
    ws.send(JSON.stringify({ type: "auth:token", success: true, message: "Token valid" }));
  } else {
    ws.send(JSON.stringify({ type: "auth:token", success: false, message: "Invalid token" }));
  }
}

// Выход пользователя
function handleLogout(ws, data) {
  ws.send(JSON.stringify({ type: "auth:logout", success: true, message: "Logout successful" }));
}

loadUsers();
