const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');

// Load environment variables
require('dotenv').config();

// Validate required environment variables
const requiredEnvVars = ['JWT_SECRET', 'MONGODB_URI'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  console.error('Missing required environment variables:', missingEnvVars.join(', '));
}

const app = express();

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

// CORS configuration - must handle preflight properly
const allowedOrigins = [
  'https://charity.furo.lk',
  'http://localhost:5173',
  'http://localhost:3000'
];

// Add CLIENT_URL from environment if set
if (process.env.CLIENT_URL) {
  const envOrigins = process.env.CLIENT_URL.split(',').map(url => url.trim());
  envOrigins.forEach(origin => {
    if (!allowedOrigins.includes(origin)) {
      allowedOrigins.push(origin);
    }
  });
}

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization']
};

app.use(cors(corsOptions));
// Handle preflight requests for all routes
app.options('*', cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'production' ? 100 : 1000,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// Logging
app.use(morgan('combined'));

// Debug CORS issues in production
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path} - Origin: ${req.headers.origin}`);
  next();
});

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Root/Info endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'OK',
    message: 'ImpactHub API is running',
    version: '1.0.0',
    endpoints: [
      '/api/health',
      '/api/auth',
      '/api/users',
      '/api/campaigns',
      '/api/donations',
      '/api/analytics',
      '/api/avatars',
      '/api/uploads',
      '/api/notifications',
      '/api/admin'
    ]
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    message: 'ImpactHub API is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'production'
  });
});

// Initialize MongoDB connection (reuse existing connections in Vercel)
let mongoConnected = false;
let connectionAttempted = false;

const connectDB = async () => {
  // If already connected, return immediately
  if (mongoConnected && mongoose.connection.readyState === 1) {
    return true;
  }

  // If connection is in progress, wait for it
  if (mongoose.connection.readyState === 2) {
    console.log('MongoDB connection already in progress, waiting...');
    await new Promise((resolve) => {
      mongoose.connection.once('connected', resolve);
      setTimeout(resolve, 15000); // Timeout after 15s
    });
    return mongoose.connection.readyState === 1;
  }

  // Attempt new connection
  try {
    if (!process.env.MONGODB_URI) {
      console.error('MONGODB_URI environment variable is not set!');
      throw new Error('MONGODB_URI is required');
    }
    
    console.log('Attempting MongoDB connection...');
    connectionAttempted = true;
    
    await mongoose.connect(process.env.MONGODB_URI, {
      retryWrites: true,
      w: 'majority',
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 10000, // Fail fast after 10s
      socketTimeoutMS: 45000,
    });
    
    mongoConnected = true;
    console.log('MongoDB connected successfully');
    return true;
  } catch (error) {
    console.error('MongoDB connection failed:', error.message);
    if (error.message.includes('ENOTFOUND') || error.message.includes('getaddrinfo')) {
      console.error('DNS resolution failed - check MONGODB_URI hostname');
    } else if (error.message.includes('authentication failed')) {
      console.error('Authentication failed - check MongoDB credentials');
    } else if (error.message.includes('timeout')) {
      console.error('Connection timeout - check MongoDB Atlas IP whitelist (allow 0.0.0.0/0 for Vercel)');
    }
    mongoConnected = false;
    return false;
  }
};

// Connect to DB on first request with error handling
app.use(async (req, res, next) => {
  try {
    const connected = await connectDB();
    if (!connected) {
      return res.status(503).json({ 
        error: 'Database connection unavailable',
        message: 'Unable to connect to MongoDB. Please check server logs.'
      });
    }
    next();
  } catch (error) {
    console.error('DB connection middleware error:', error);
    res.status(503).json({ 
      error: 'Database connection failed',
      message: process.env.NODE_ENV === 'development' ? error.message : 'Service temporarily unavailable'
    });
  }
});

// Routes - fix relative paths for serverless environment
const routesPath = path.join(__dirname, '../routes');
app.use('/api/auth', require(path.join(routesPath, 'auth')));
app.use('/api/users', require(path.join(routesPath, 'users')));
app.use('/api/campaigns', require(path.join(routesPath, 'campaigns')));
app.use('/api/donations', require(path.join(routesPath, 'donations')));
app.use('/api/analytics', require(path.join(routesPath, 'analytics')));
app.use('/api/avatars', require(path.join(routesPath, 'avatars')));
app.use('/api/uploads', require(path.join(routesPath, 'uploads')));
app.use('/api/notifications', require(path.join(routesPath, 'notifications')));
app.use('/api/admin', require(path.join(routesPath, 'admin')));

// Serve static files for uploads
app.use('/uploads', express.static(path.join(__dirname, '../uploads'), {
  setHeaders: (res, filePath) => {
    res.set('Access-Control-Allow-Origin', process.env.CLIENT_URL || 'http://localhost:5173');
    res.set('Access-Control-Allow-Credentials', 'true');
    res.set('Cross-Origin-Resource-Policy', 'cross-origin');
    res.set('Cache-Control', 'public, max-age=31536000');
  }
}));

// Error handling middleware (must be last)
app.use((err, req, res, next) => {
  console.error('Error:', err.stack);
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      error: 'Validation Error',
      details: Object.values(err.errors).map(e => e.message)
    });
  }
  
  if (err.name === 'CastError') {
    return res.status(400).json({
      error: 'Invalid ID format'
    });
  }
  
  if (err.code === 11000) {
    return res.status(400).json({
      error: 'Duplicate field value',
      details: err.message
    });
  }
  
  res.status(err.status || 500).json({ 
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

// 404 handler (must be after all other routes)
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    path: req.originalUrl 
  });
});

module.exports = app;
