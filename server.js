import express from "express";
import http from "http";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Server } from "socket.io";
import mongoose from "mongoose";
import { MongoMemoryServer } from "mongodb-memory-server";

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const JWT_SECRET = "secret";

// ✅ MongoDB In-Memory setup
const startDB = async () => {
  const mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  await mongoose.connect(uri);
  console.log("✅ Connected to in-memory MongoDB");

  // 🧱 Define Mongoose Schemas
  const userSchema = new mongoose.Schema({
    username: String,
    passwordHash: String,
  });

  const pollSchema = new mongoose.Schema({
    question: String,
    options: [{ text: String, votes: Number }],
    createdBy: mongoose.Schema.Types.ObjectId,
  });

  const User = mongoose.model("User", userSchema);
  const Poll = mongoose.model("Poll", pollSchema);

  // 🔐 JWT middleware
  function authMiddleware(req, res, next) {
    const token = req.headers["authorization"];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token.split(" ")[1], JWT_SECRET);
      req.user = decoded;
      next();
    } catch {
      res.status(401).json({ error: "Invalid token" });
    }
  }

  // 👥 Register
  app.post("/api/register", async (req, res) => {
    const { username, password } = req.body;
    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ error: "User exists" });

    const hash = await bcrypt.hash(password, 10);
    const user = new User({ username, passwordHash: hash });
    await user.save();
    res.json({ message: "User created" });
  });

  // 🔑 Login
  app.post("/api/login", async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: "User not found" });
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(400).json({ error: "Invalid password" });

    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET);
    res.json({ token });
  });

  // 📊 Create poll
  app.post("/api/polls", authMiddleware, async (req, res) => {
    const { question, options } = req.body;
    const poll = new Poll({
      question,
      options: options.map((text) => ({ text, votes: 0 })),
      createdBy: req.user.id,
    });
    await poll.save();

    const allPolls = await Poll.find();
    io.emit("pollsUpdate", allPolls);
    res.json(poll);
  });

  // 🧾 Get all polls
  app.get("/api/polls", async (req, res) => {
    const allPolls = await Poll.find();
    res.json(allPolls);
  });

  // ⚡ Socket.io
  io.on("connection", (socket) => {
    console.log("🟢 New user connected");
    socket.emit("pollsUpdate");

    socket.on("vote", async ({ pollId, optionIndex }) => {
      const poll = await Poll.findById(pollId);
      if (poll && poll.options[optionIndex]) {
        poll.options[optionIndex].votes++;
        await poll.save();

        const updatedPolls = await Poll.find();
        io.emit("pollsUpdate", updatedPolls);
      }
    });

    socket.on("disconnect", () => console.log("🔴 User disconnected"));
  });

  // 🚀 Start server
  server.listen(3000, () =>
    console.log("Server running on http://localhost:3000")
  );
};

startDB();
