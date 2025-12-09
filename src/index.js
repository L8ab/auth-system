const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
app.use(express.json());

// Auth routes
app.post('/api/register', async (req, res) => {
  const authService = require('./services/authService');
  try {
    const result = await authService.register(req.body);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  const authService = require('./services/authService');
  try {
    const result = await authService.login(req.body.email, req.body.password);
    res.json(result);
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/auth', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Auth System running on port ${PORT}`);
});
