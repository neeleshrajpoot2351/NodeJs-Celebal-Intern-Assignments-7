require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;
const cors = require('cors');
app.use(cors());


app.use(express.json());


const dummyUser = {
  id: 1,
  username: 'neelesh',
  passwordHash: bcrypt.hashSync('myPassword123', 10)
};


app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (username !== dummyUser.username) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  const isMatch = await bcrypt.compare(password, dummyUser.passwordHash);
  if (!isMatch) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  const payload = { id: dummyUser.id, username: dummyUser.username };
  const token = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.TOKEN_EXPIRATION
  });

  res.json({ token });
});


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) return res.status(401).json({ message: 'Token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });

    req.user = user;
    next();
  });
}


app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'You accessed protected data!', user: req.user });
});

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
