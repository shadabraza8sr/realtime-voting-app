const express = require('express');
const http = require('http');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const JWT_SECRET = 'secret';
let users = [];
let polls = [];
let pollIdCounter = 1;

// JWT middleware
function authMiddleware(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
        const decoded = jwt.verify(token.split(' ')[1], JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// Auth routes
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (users.find(u => u.username === username)) return res.status(400).json({ error: 'User exists' });
    const hash = await bcrypt.hash(password, 10);
    const user = { id: users.length+1, username, passwordHash: hash };
    users.push(user);
    res.json({ message: 'User created' });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(400).json({ error: 'Invalid password' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
    res.json({ token });
});

// Poll routes
app.post('/api/polls', authMiddleware, (req, res) => {
    const { question, options } = req.body;
    const poll = { id: pollIdCounter++, question, options: options.map(text => ({ text, votes: 0 })), createdBy: req.user.id };
    polls.push(poll);
    io.emit('pollsUpdate', polls);
    res.json(poll);
});

app.get('/api/polls', (req, res) => {
    res.json(polls);
});

// Socket.io
io.on('connection', (socket) => {
    console.log('New user connected');
    socket.emit('pollsUpdate', polls);

    socket.on('vote', ({ pollId, optionIndex }) => {
        const poll = polls.find(p => p.id === pollId);
        if (poll) {
            poll.options[optionIndex].votes++;
            io.emit('pollsUpdate', polls);
        }
    });

    socket.on('disconnect', () => console.log('User disconnected'));
});

server.listen(3000, () => console.log('Server running on http://localhost:3000'));
