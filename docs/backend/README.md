# Backend Development Guide

## Overview
This guide covers backend development best practices for building scalable, secure, and maintainable applications. It includes server architecture, database design, API development, and authentication strategies.

## Table of Contents
1. [Server Architecture](#server-architecture)
2. [Database Design](#database-design)
3. [API Development](#api-development)
4. [Authentication & Authorization](#authentication--authorization)
5. [Error Handling](#error-handling)
6. [Performance Optimization](#performance-optimization)
7. [Security Best Practices](#security-best-practices)

## Server Architecture

### 1. Node.js with Express.js

```javascript
// Basic Express.js Server Setup
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// Compression
app.use(compression());

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api/users', require('./routes/users'));
app.use('/api/products', require('./routes/products'));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

### 2. Python with FastAPI

```python
# FastAPI Server Setup
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="Scalable API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Models
class UserCreate(BaseModel):
    email: str
    password: str
    name: str

class UserResponse(BaseModel):
    id: int
    email: str
    name: str

# Routes
@app.post("/users/", response_model=UserResponse)
async def create_user(user: UserCreate):
    # Implementation here
    pass

@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: int, token: str = Depends(security)):
    # Implementation here
    pass

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### 3. Java with Spring Boot

```java
// Spring Boot Application
@SpringBootApplication
@EnableJpaRepositories
public class ScalableApplication {
    public static void main(String[] args) {
        SpringApplication.run(ScalableApplication.class, args);
    }
}

// Controller
@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = {"http://localhost:3000"})
public class UserController {
    
    @Autowired
    private UserService userService;
    
    @PostMapping
    public ResponseEntity<User> createUser(@RequestBody @Valid UserCreateRequest request) {
        User user = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }
    
    @GetMapping("/{id}")
    public ResponseEntity<User> getUser(@PathVariable Long id) {
        User user = userService.getUserById(id);
        return ResponseEntity.ok(user);
    }
}
```

## Database Design

### 1. Database Schema Design

```sql
-- Users Table
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Products Table
CREATE TABLE products (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    stock_quantity INTEGER DEFAULT 0,
    category_id BIGINT REFERENCES categories(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Orders Table
CREATE TABLE orders (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id),
    status VARCHAR(50) DEFAULT 'pending',
    total_amount DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Order Items Table
CREATE TABLE order_items (
    id BIGSERIAL PRIMARY KEY,
    order_id BIGINT REFERENCES orders(id),
    product_id BIGINT REFERENCES products(id),
    quantity INTEGER NOT NULL,
    unit_price DECIMAL(10,2) NOT NULL
);

-- Indexes for Performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_orders_user_id ON orders(user_id);
CREATE INDEX idx_products_category ON products(category_id);
CREATE INDEX idx_order_items_order_id ON order_items(order_id);
```

### 2. Database Connection Pooling

```javascript
// Node.js with PostgreSQL
const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  max: 20, // Maximum number of clients in the pool
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Connection pool event handlers
pool.on('connect', () => {
  console.log('Connected to database');
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
  process.exit(-1);
});

module.exports = pool;
```

### 3. Database Migrations

```javascript
// Migration Example
exports.up = function(knex) {
  return knex.schema.createTable('users', function(table) {
    table.increments('id').primary();
    table.string('email').unique().notNullable();
    table.string('password_hash').notNullable();
    table.string('name').notNullable();
    table.timestamps(true, true);
    table.boolean('is_active').defaultTo(true);
  });
};

exports.down = function(knex) {
  return knex.schema.dropTable('users');
};
```

## API Development

### 1. RESTful API Design

```javascript
// RESTful API Routes
const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const auth = require('../middleware/auth');

// GET /api/users - Get all users (with pagination)
router.get('/', auth, userController.getUsers);

// GET /api/users/:id - Get specific user
router.get('/:id', auth, userController.getUserById);

// POST /api/users - Create new user
router.post('/', userController.createUser);

// PUT /api/users/:id - Update user
router.put('/:id', auth, userController.updateUser);

// DELETE /api/users/:id - Delete user
router.delete('/:id', auth, userController.deleteUser);

module.exports = router;
```

### 2. API Response Format

```javascript
// Standard API Response Format
class ApiResponse {
  static success(data, message = 'Success', statusCode = 200) {
    return {
      success: true,
      message,
      data,
      timestamp: new Date().toISOString(),
      statusCode
    };
  }

  static error(message, statusCode = 400, errors = null) {
    return {
      success: false,
      message,
      errors,
      timestamp: new Date().toISOString(),
      statusCode
    };
  }
}

// Usage in controller
const getUsers = async (req, res) => {
  try {
    const { page = 1, limit = 10, search } = req.query;
    const users = await UserService.getUsers({ page, limit, search });
    
    res.json(ApiResponse.success(users, 'Users retrieved successfully'));
  } catch (error) {
    res.status(500).json(ApiResponse.error('Failed to retrieve users', 500));
  }
};
```

### 3. API Versioning

```javascript
// API Versioning Strategy
const express = require('express');
const app = express();

// Version 1 API
app.use('/api/v1/users', require('./routes/v1/users'));
app.use('/api/v1/products', require('./routes/v1/products'));

// Version 2 API
app.use('/api/v2/users', require('./routes/v2/users'));
app.use('/api/v2/products', require('./routes/v2/products'));

// Default to latest version
app.use('/api/users', require('./routes/v2/users'));
app.use('/api/products', require('./routes/v2/products'));
```

## Authentication & Authorization

### 1. JWT Authentication

```javascript
// JWT Authentication Middleware
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Generate JWT Token
const generateToken = (userId) => {
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
};

// Verify JWT Token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Password Hashing
const hashPassword = async (password) => {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
};

const comparePassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};
```

### 2. Role-Based Access Control (RBAC)

```javascript
// RBAC Middleware
const checkRole = (requiredRoles) => {
  return async (req, res, next) => {
    try {
      const user = await User.findById(req.userId);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      if (!requiredRoles.includes(user.role)) {
        return res.status(403).json({ error: 'Insufficient permissions' });
      }

      req.user = user;
      next();
    } catch (error) {
      res.status(500).json({ error: 'Authorization failed' });
    }
  };
};

// Usage
router.get('/admin/users', 
  verifyToken, 
  checkRole(['admin', 'super_admin']), 
  userController.getAllUsers
);
```

### 3. OAuth 2.0 Integration

```javascript
// OAuth 2.0 with Google
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ googleId: profile.id });
      
      if (!user) {
        user = await User.create({
          googleId: profile.id,
          email: profile.emails[0].value,
          name: profile.displayName
        });
      }
      
      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  }
));

// OAuth routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    const token = generateToken(req.user.id);
    res.redirect(`/dashboard?token=${token}`);
  }
);
```

## Error Handling

### 1. Global Error Handler

```javascript
// Global Error Handler
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);

  // Database errors
  if (err.name === 'SequelizeValidationError') {
    return res.status(400).json({
      error: 'Validation Error',
      details: err.errors.map(e => ({
        field: e.path,
        message: e.message
      }))
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      error: 'Invalid token'
    });
  }

  // Default error
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error'
  });
};

app.use(errorHandler);
```

### 2. Custom Error Classes

```javascript
// Custom Error Classes
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends AppError {
  constructor(message) {
    super(message, 400);
  }
}

class AuthenticationError extends AppError {
  constructor(message = 'Authentication failed') {
    super(message, 401);
  }
}

class AuthorizationError extends AppError {
  constructor(message = 'Insufficient permissions') {
    super(message, 403);
  }
}
```

## Performance Optimization

### 1. Database Query Optimization

```javascript
// Optimized Database Queries
const getUsersWithOrders = async (page = 1, limit = 10) => {
  const offset = (page - 1) * limit;
  
  const users = await User.findAll({
    include: [{
      model: Order,
      attributes: ['id', 'total_amount', 'status'],
      required: false
    }],
    attributes: ['id', 'name', 'email'],
    limit,
    offset,
    order: [['created_at', 'DESC']]
  });

  return users;
};

// Using database indexes
const searchProducts = async (searchTerm) => {
  return await Product.findAll({
    where: {
      [Op.or]: [
        { name: { [Op.iLike]: `%${searchTerm}%` } },
        { description: { [Op.iLike]: `%${searchTerm}%` } }
      ]
    },
    include: [{
      model: Category,
      attributes: ['name']
    }]
  });
};
```

### 2. Caching Strategies

```javascript
// Redis Caching
const redis = require('redis');
const client = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT
});

const cacheMiddleware = (duration = 300) => {
  return async (req, res, next) => {
    const key = `cache:${req.originalUrl}`;
    
    try {
      const cached = await client.get(key);
      if (cached) {
        return res.json(JSON.parse(cached));
      }
      
      res.sendResponse = res.json;
      res.json = (body) => {
        client.setex(key, duration, JSON.stringify(body));
        res.sendResponse(body);
      };
      
      next();
    } catch (error) {
      next();
    }
  };
};

// Usage
router.get('/products', cacheMiddleware(600), productController.getProducts);
```

## Security Best Practices

### 1. Input Validation

```javascript
// Input Validation with Joi
const Joi = require('joi');

const userSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])')).required(),
  name: Joi.string().min(2).max(50).required()
});

const validateUser = (req, res, next) => {
  const { error } = userSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      error: 'Validation Error',
      details: error.details.map(detail => detail.message)
    });
  }
  
  next();
};
```

### 2. SQL Injection Prevention

```javascript
// Using Parameterized Queries
const getUserById = async (userId) => {
  const query = 'SELECT * FROM users WHERE id = $1 AND is_active = $2';
  const values = [userId, true];
  
  const result = await pool.query(query, values);
  return result.rows[0];
};

// Using ORM (Sequelize)
const getUserByEmail = async (email) => {
  return await User.findOne({
    where: { email }
  });
};
```

### 3. Rate Limiting

```javascript
// Advanced Rate Limiting
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');

const authLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'auth_limit:'
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'api_limit:'
  }),
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many API requests, please try again later'
});

app.use('/auth/login', authLimiter);
app.use('/api/', apiLimiter);
```

This backend development guide provides comprehensive coverage of modern backend development practices, including server architecture, database design, API development, authentication, error handling, performance optimization, and security best practices. Each section includes practical code examples and implementation strategies for building scalable and secure applications.
