const express = require("express");
const bcrypt = require("bcrypt");
const db = require("./database");

const app = express();
app.use(express.json());

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Missing fields" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashedPassword],
    function (err) {
      if (err) {
        return res.status(400).json({ message: "User already exists" });
      }

      res.json({ message: "User registered successfully" });
    }
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (err || !user) {
        return res.status(400).json({ message: "User not found" });
      }

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(401).json({ message: "Incorrect password" });
      }

      res.json({ message: "Login successful" });
    }
  );
});

app.listen(3000,()=>{
    console.log("Server running on http://localhost:3000");
});