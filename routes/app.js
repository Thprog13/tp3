// app.js
const express = require('express');
const app = express();
const cors = require('cors');
const knex = require('./knex');
require('dotenv').config();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
const authRoutes = require('./routes/authRoutes');
const ticketRoutes = require('./routes/ticketRoutes');

app.use('/api/auth', authRoutes);
app.use('/api/tickets', ticketRoutes);

app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
