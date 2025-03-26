// index.js
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const connection = require("./db");

const app = express();
const PORT = process.env.PORT || 5000; // تغییر پورت
const JWT_SECRET = "your_jwt_secret_key";

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

// اعتبارسنجی فرمت تاریخ
const validateDate = (dateString) => {
  const regex = /^\d{4}-\d{2}-\d{2}$/;
  if (!regex.test(dateString)) return false;
  const date = new Date(dateString);
  return date instanceof Date && !isNaN(date);
};

// Middleware برای اعتبارسنجی توکن
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: "Invalid token." });
  }
};

// ثبت‌نام کاربر
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }

  try {
    const checkUserQuery = "SELECT * FROM users WHERE username = ?";
    connection.query(checkUserQuery, [username], async (err, results) => {
      if (err) {
        console.error("Error checking user:", err);
        return res.status(500).json({ error: "Database error" });
      }
      if (results.length > 0) {
        return res.status(400).json({ error: "Username already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const insertUserQuery =
        "INSERT INTO users (username, password) VALUES (?, ?)";
      connection.query(
        insertUserQuery,
        [username, hashedPassword],
        (err, result) => {
          if (err) {
            if (err.code === "ER_DUP_ENTRY") {
              return res.status(400).json({ error: "Username already exists" });
            }
            console.error("Error registering user:", err);
            return res.status(500).json({ error: "Database error" });
          }
          res.status(201).json({ message: "User registered successfully" });
        }
      );
    });
  } catch (err) {
    console.error("Error in register:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ورود کاربر
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }

  const query = "SELECT * FROM users WHERE username = ?";
  connection.query(query, [username], async (err, results) => {
    if (err) {
      console.error("Error logging in:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (results.length === 0) {
      return res.status(400).json({ error: "Invalid username or password" });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid username or password" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );
    res.json({ token });
  });
});

// API Endpoints (با احراز هویت)

// دریافت وظایف برای یک تاریخ خاص
app.get("/todos/:date", authenticateToken, (req, res) => {
  const { date } = req.params;
  const userId = req.user.id;
  if (!validateDate(date)) {
    return res
      .status(400)
      .json({ error: "Invalid date format. Use YYYY-MM-DD" });
  }
  const query = "SELECT * FROM todos WHERE date = ? AND user_id = ?";
  connection.query(query, [date, userId], (err, results) => {
    if (err) {
      console.error("Error fetching todos:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(results);
  });
});

// اضافه کردن وظیفه جدید
app.post("/todos", authenticateToken, (req, res) => {
  const { text, date } = req.body;
  const userId = req.user.id;
  if (!text || !date) {
    return res.status(400).json({ error: "Text and date are required" });
  }
  if (!validateDate(date)) {
    return res
      .status(400)
      .json({ error: "Invalid date format. Use YYYY-MM-DD" });
  }
  const query =
    "INSERT INTO todos (text, date, completed, user_id) VALUES (?, ?, ?, ?)";
  connection.query(query, [text, date, false, userId], (err, result) => {
    if (err) {
      console.error("Error adding todo:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json({
      id: result.insertId,
      text,
      date,
      completed: false,
      user_id: userId,
    });
  });
});

// به‌روزرسانی وضعیت وظیفه
app.put("/todos/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  const { completed } = req.body;
  const userId = req.user.id;
  const query = "UPDATE todos SET completed = ? WHERE id = ? AND user_id = ?";
  connection.query(query, [completed, id, userId], (err) => {
    if (err) {
      console.error("Error updating todo:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ message: "Todo updated successfully" });
  });
});

// ویرایش متن وظیفه
app.put("/todos/:id/text", authenticateToken, (req, res) => {
  const { id } = req.params;
  const { text } = req.body;
  const userId = req.user.id;
  if (!text) {
    return res.status(400).json({ error: "Text is required" });
  }
  const query = "UPDATE todos SET text = ? WHERE id = ? AND user_id = ?";
  connection.query(query, [text, id, userId], (err) => {
    if (err) {
      console.error("Error updating todo text:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ message: "Todo text updated successfully" });
  });
});

// حذف وظیفه
app.delete("/todos/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  const query = "DELETE FROM todos WHERE id = ? AND user_id = ?";
  connection.query(query, [id, userId], (err) => {
    if (err) {
      console.error("Error deleting todo:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ message: "Todo deleted successfully" });
  });
});

// Middleware برای مدیریت خطاها
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ error: "Something went wrong on the server" });
});

// راه‌اندازی سرور
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
