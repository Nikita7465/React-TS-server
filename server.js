const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const saltRounds = 10;
const databaseFile = "usersdb.db";

const app = express();
const PORT = 3000;

app.use(bodyParser.json());
app.use(cors());

const generateSecretKey = () => {
  return crypto.randomBytes(32).toString("hex");
};

const createJWT = (payload, secretKey, expiresIn = "30d") => {
  return jwt.sign(payload, secretKey, { expiresIn });
};

app.post("/register", async (req, res) => {
  const db = new sqlite3.Database(databaseFile);
  try {
    const { username, email, password } = req.body;

    await new Promise((resolve, reject) => {
      db.run(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, email TEXT UNIQUE, password TEXT)",
        (err) => {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        }
      );
    });

    const existingUser = await new Promise((resolve, reject) => {
      db.get(
        "SELECT * FROM users WHERE email = ?",
        [email],
        (err, existingUser) => {
          if (err) {
            reject(err);
          } else {
            resolve(existingUser);
          }
        }
      );
    });

    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        [username, email, hashedPassword],
        (insertErr) => {
          if (insertErr) {
            reject(insertErr);
          } else {
            resolve();
            db.close();
          }
        }
      );
    });

    const secretKey = generateSecretKey();

    const userData = {
      username: username,
      email: email,
    };

    const token = createJWT(userData, secretKey);

    const user = {
      jwt: token,
      userData,
    };

    return res
      .status(200)
      .json({ message: "User successfully registered", user });
  } catch (error) {
    console.error("Error:", error);
    return res.status(500).json({ message: "Failed to register user" });
  }
});

app.post("/auth", async (req, res) => {
  const db = new sqlite3.Database(databaseFile);
  try {
    const { email, password } = req.body;

    const existingUser = await new Promise((resolve, reject) => {
      db.get("SELECT * FROM users WHERE email = ?", [email], (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row);
        }
      });
    });

    if (existingUser) {
      const passwordMatch = await bcrypt.compare(
        password,
        existingUser.password
      );

      if (passwordMatch) {
        db.close();

        const secretKey = generateSecretKey();

        const userData = {
          username: existingUser.username,
          email: existingUser.email,
        };

        const token = createJWT(userData, secretKey);

        const user = {
          jwt: token,
          userData,
        };
        res
          .status(200)
          .json({ message: "User authenticated successfully", user });
      } else {
        res.status(401).json({ message: "Incorrect email or password" });
      }
    } else {
      res.status(401).json({ message: "Incorrect email or password" });
    }
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
