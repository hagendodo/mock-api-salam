const express = require("express");
const mysql = require("mysql2");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());

const SECRET_KEY = "your_secret_key"; // replace with a strong secret key
const SALT_ROUNDS = 10; // for password hashing

// MySQL connection setup
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "", // replace with your MySQL password
  database: "mock_salam", // replace with your database name
});

db.connect((err) => {
  if (err) throw err;
  console.log("Connected to the database");
});

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  // Get the 'Authorization' header
  const authHeader = req.headers["authorization"];

  // Check if the 'Authorization' header is present
  if (!authHeader) {
    return res.status(403).send({ message: "No token provided" });
  }

  // Split the header into "Bearer <token>"
  const token = authHeader.split(" ")[1]; // The token is the second part

  // If the token does not exist after splitting, return an error
  if (!token) {
    return res.status(403).send({ message: "Token is missing" });
  }

  // Verify the token
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(500).send({ message: "Failed to authenticate token" });
    }

    // Store 'nim' from token payload in request object
    req.nim = decoded.nim;

    // Proceed to the next middleware or route handler
    next();
  });
}

// Route to check if token is valid
app.get("/check-token", verifyToken, (req, res) => {
  // If token is valid, send success message
  res.status(200).send({ message: "Token is valid" });
});

// POST /register route for new user registration
app.post("/register", (req, res) => {
  const { name, nim, password, jurusan, fakultas } = req.body;

  // Check if all fields are provided
  if (!name || !nim || !password || !jurusan || !fakultas) {
    return res.status(400).send({ message: "All fields are required" });
  }

  // Hash the password before storing it
  const hashedPassword = bcrypt.hashSync(password, SALT_ROUNDS);

  const query =
    "INSERT INTO users (name, nim, password, jurusan, fakultas) VALUES (?, ?, ?, ?, ?)";
  db.query(
    query,
    [name, nim, hashedPassword, jurusan, fakultas],
    (err, result) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(409).send({ message: "NIM already registered" });
        }
        return res.status(500).send({ message: "Database error" });
      }
      res.status(201).send({ message: "User registered successfully" });
    }
  );
});

// POST /login route for user authentication
app.post("/login", (req, res) => {
  const { nim, password } = req.body;

  // Query the database to find the user by their 'nim'
  const query = "SELECT * FROM users WHERE nim = ?";
  db.query(query, [nim], (err, results) => {
    if (err) return res.status(500).send("Server error");

    if (results.length === 0) {
      // If no user found with the provided nim
      return res.status(404).send({ message: "User not found" });
    }

    const user = results[0]; // Get the first matching user

    // Compare the raw password provided by the user with the hashed password in the database
    const passwordIsValid = bcrypt.compareSync(password, user.password);

    if (!passwordIsValid) {
      // If the passwords don't match, return an invalid password error
      return res.status(401).send({ message: "Invalid password" });
    }

    // Generate a token using the user's nim
    const token = jwt.sign({ nim: user.nim }, SECRET_KEY, { expiresIn: "1h" });

    // Send the generated token as the response
    res.send({ token });
  });
});

// GET /profile route to fetch user profile, with token verification
app.get("/profile", verifyToken, (req, res) => {
  const query = "SELECT name, nim, jurusan, fakultas FROM users WHERE nim = ?";
  db.query(query, [req.nim], (err, results) => {
    if (err) return res.status(500).send("Server error");
    if (results.length === 0)
      return res.status(404).send({ message: "Profile not found" });

    res.send(results[0]);
  });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
