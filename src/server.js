const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');

const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');

dotenv.config();

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());

// Connect Database
connectDB();

// Health Check Route
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    message: 'Nutrivita API running',
  });
});

// Mount Authentication Routes
app.use('/api/auth', authRoutes);

// Server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`[Server] Nutrivita Backend listening on port ${PORT}`);
});