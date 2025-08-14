# Security Guide

## Overview
This guide covers comprehensive security practices for building secure, scalable applications. It includes authentication, authorization, data protection, vulnerability prevention, and security monitoring strategies.

## Table of Contents
1. [Security Fundamentals](#security-fundamentals)
2. [Authentication & Authorization](#authentication--authorization)
3. [Data Protection](#data-protection)
4. [API Security](#api-security)
5. [Infrastructure Security](#infrastructure-security)
6. [Security Monitoring](#security-monitoring)
7. [Compliance & Standards](#compliance--standards)

## Security Fundamentals

### 1. Security Principles

```javascript
// Security Configuration
const securityConfig = {
  // Principle of Least Privilege
  permissions: {
    user: ['read:own', 'write:own'],
    moderator: ['read:all', 'write:own', 'delete:own'],
    admin: ['read:all', 'write:all', 'delete:all']
  },
  
  // Defense in Depth
  layers: [
    'network_security',
    'application_security', 
    'data_security',
    'access_control'
  ],
  
  // Fail Securely
  errorHandling: {
    hideInternalErrors: true,
    logSecurityEvents: true,
    sanitizeOutput: true
  }
};
```

### 2. Threat Modeling

```javascript
// STRIDE Threat Model
const threatModel = {
  spoofing: {
    threats: ['fake_authentication', 'session_hijacking'],
    mitigations: ['strong_auth', 'session_management', 'HTTPS']
  },
  tampering: {
    threats: ['data_modification', 'code_injection'],
    mitigations: ['input_validation', 'output_encoding', 'integrity_checks']
  },
  repudiation: {
    threats: ['deny_actions', 'audit_bypass'],
    mitigations: ['logging', 'digital_signatures', 'audit_trails']
  },
  information_disclosure: {
    threats: ['data_exposure', 'error_leakage'],
    mitigations: ['encryption', 'access_control', 'error_handling']
  },
  denial_of_service: {
    threats: ['resource_exhaustion', 'service_unavailability'],
    mitigations: ['rate_limiting', 'resource_limits', 'monitoring']
  },
  elevation_of_privilege: {
    threats: ['privilege_escalation', 'unauthorized_access'],
    mitigations: ['authorization', 'principle_of_least_privilege']
  }
};
```

## Authentication & Authorization

### 1. Multi-Factor Authentication (MFA)

```javascript
// MFA Implementation
const mfaService = {
  // TOTP (Time-based One-Time Password)
  generateTOTP: async (secret) => {
    const speakeasy = require('speakeasy');
    return speakeasy.totp({
      secret: secret,
      encoding: 'base32',
      window: 2 // Allow 2 time steps for clock skew
    });
  },

  // SMS-based MFA
  sendSMS: async (phoneNumber, code) => {
    const twilio = require('twilio');
    const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
    
    return await client.messages.create({
      body: `Your verification code is: ${code}`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phoneNumber
    });
  },

  // Email-based MFA
  sendEmail: async (email, code) => {
    const nodemailer = require('nodemailer');
    const transporter = nodemailer.createTransporter({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: true,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    return await transporter.sendMail({
      from: process.env.FROM_EMAIL,
      to: email,
      subject: 'Verification Code',
      html: `<p>Your verification code is: <strong>${code}</strong></p>`
    });
  }
};

// MFA Middleware
const requireMFA = async (req, res, next) => {
  const { mfaCode } = req.body;
  const user = req.user;

  if (!user.mfaEnabled) {
    return next();
  }

  if (!mfaCode) {
    return res.status(400).json({ error: 'MFA code required' });
  }

  try {
    const isValid = await mfaService.verifyTOTP(user.mfaSecret, mfaCode);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid MFA code' });
    }
    next();
  } catch (error) {
    res.status(500).json({ error: 'MFA verification failed' });
  }
};
```

### 2. OAuth 2.0 & OpenID Connect

```javascript
// OAuth 2.0 Implementation
const oauth2Config = {
  authorizationServer: {
    authorizeEndpoint: '/oauth/authorize',
    tokenEndpoint: '/oauth/token',
    userinfoEndpoint: '/oauth/userinfo',
    jwksEndpoint: '/oauth/jwks'
  },
  
  clients: [
    {
      clientId: 'web_app',
      clientSecret: process.env.WEB_APP_SECRET,
      redirectUris: ['https://app.example.com/callback'],
      grantTypes: ['authorization_code', 'refresh_token'],
      scopes: ['read', 'write']
    }
  ],
  
  scopes: {
    read: 'Read user data',
    write: 'Modify user data',
    admin: 'Administrative access'
  }
};

// OAuth 2.0 Authorization Endpoint
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, scope, state, response_type } = req.query;
  
  // Validate client
  const client = oauth2Config.clients.find(c => c.clientId === client_id);
  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'invalid_client' });
  }
  
  // Generate authorization code
  const authCode = crypto.randomBytes(32).toString('hex');
  
  // Store authorization code (with expiration)
  await redis.setex(`auth_code:${authCode}`, 600, JSON.stringify({
    clientId: client_id,
    userId: req.user.id,
    scope: scope,
    redirectUri: redirect_uri
  }));
  
  // Redirect with authorization code
  const redirectUrl = `${redirect_uri}?code=${authCode}&state=${state}`;
  res.redirect(redirectUrl);
});

// OAuth 2.0 Token Endpoint
app.post('/oauth/token', async (req, res) => {
  const { grant_type, code, client_id, client_secret, redirect_uri } = req.body;
  
  if (grant_type === 'authorization_code') {
    // Validate client credentials
    const client = oauth2Config.clients.find(c => 
      c.clientId === client_id && c.clientSecret === client_secret
    );
    
    if (!client) {
      return res.status(401).json({ error: 'invalid_client' });
    }
    
    // Validate authorization code
    const authCodeData = await redis.get(`auth_code:${code}`);
    if (!authCodeData) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    
    const { userId, scope } = JSON.parse(authCodeData);
    
    // Generate access token
    const accessToken = jwt.sign(
      { userId, scope, clientId: client_id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    // Generate refresh token
    const refreshToken = crypto.randomBytes(32).toString('hex');
    
    // Store refresh token
    await redis.setex(`refresh_token:${refreshToken}`, 86400, JSON.stringify({
      userId,
      clientId: client_id,
      scope
    }));
    
    // Delete authorization code
    await redis.del(`auth_code:${code}`);
    
    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: scope
    });
  }
});
```

### 3. Role-Based Access Control (RBAC)

```javascript
// RBAC Implementation
class RBAC {
  constructor() {
    this.roles = new Map();
    this.permissions = new Map();
    this.userRoles = new Map();
  }

  // Define roles and permissions
  defineRole(role, permissions) {
    this.roles.set(role, permissions);
  }

  // Assign role to user
  assignRole(userId, role) {
    if (!this.roles.has(role)) {
      throw new Error(`Role ${role} does not exist`);
    }
    
    if (!this.userRoles.has(userId)) {
      this.userRoles.set(userId, new Set());
    }
    this.userRoles.get(userId).add(role);
  }

  // Check if user has permission
  hasPermission(userId, permission) {
    const userRoles = this.userRoles.get(userId) || new Set();
    
    for (const role of userRoles) {
      const rolePermissions = this.roles.get(role) || [];
      if (rolePermissions.includes(permission)) {
        return true;
      }
    }
    return false;
  }

  // Get user permissions
  getUserPermissions(userId) {
    const userRoles = this.userRoles.get(userId) || new Set();
    const permissions = new Set();
    
    for (const role of userRoles) {
      const rolePermissions = this.roles.get(role) || [];
      rolePermissions.forEach(permission => permissions.add(permission));
    }
    
    return Array.from(permissions);
  }
}

// Initialize RBAC
const rbac = new RBAC();

// Define roles and permissions
rbac.defineRole('user', [
  'read:own_profile',
  'update:own_profile',
  'read:own_posts',
  'create:own_posts',
  'update:own_posts',
  'delete:own_posts'
]);

rbac.defineRole('moderator', [
  'read:all_posts',
  'update:any_post',
  'delete:any_post',
  'ban:user',
  'unban:user'
]);

rbac.defineRole('admin', [
  'read:all_data',
  'update:all_data',
  'delete:all_data',
  'manage:users',
  'manage:roles',
  'system:config'
]);

// RBAC Middleware
const requirePermission = (permission) => {
  return (req, res, next) => {
    const userId = req.user.id;
    
    if (!rbac.hasPermission(userId, permission)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
};

// Usage in routes
app.get('/admin/users', 
  requirePermission('manage:users'),
  userController.getAllUsers
);

app.delete('/posts/:id',
  requirePermission('delete:any_post'),
  postController.deletePost
);
```

## Data Protection

### 1. Data Encryption

```javascript
// Encryption Service
const crypto = require('crypto');

class EncryptionService {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.keyLength = 32;
    this.ivLength = 16;
    this.tagLength = 16;
  }

  // Generate encryption key
  generateKey() {
    return crypto.randomBytes(this.keyLength);
  }

  // Encrypt data
  encrypt(data, key) {
    const iv = crypto.randomBytes(this.ivLength);
    const cipher = crypto.createCipher(this.algorithm, key);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      tag: tag.toString('hex')
    };
  }

  // Decrypt data
  decrypt(encryptedData, key, iv, tag) {
    const decipher = crypto.createDecipher(this.algorithm, key);
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  // Hash password
  hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return `${salt}:${hash}`;
  }

  // Verify password
  verifyPassword(password, hashedPassword) {
    const [salt, hash] = hashedPassword.split(':');
    const verifyHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(verifyHash, 'hex'));
  }
}

// Database encryption middleware
const encryptSensitiveData = (fields) => {
  return (req, res, next) => {
    const encryptionService = new EncryptionService();
    const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    
    fields.forEach(field => {
      if (req.body[field]) {
        const encrypted = encryptionService.encrypt(req.body[field], key);
        req.body[`${field}_encrypted`] = encrypted.encrypted;
        req.body[`${field}_iv`] = encrypted.iv;
        req.body[`${field}_tag`] = encrypted.tag;
        delete req.body[field];
      }
    });
    
    next();
  };
};

// Usage
app.post('/users',
  encryptSensitiveData(['ssn', 'credit_card']),
  userController.createUser
);
```

### 2. Data Masking & Anonymization

```javascript
// Data Masking Service
class DataMaskingService {
  // Mask sensitive data
  maskData(data, type) {
    switch (type) {
      case 'email':
        return this.maskEmail(data);
      case 'phone':
        return this.maskPhone(data);
      case 'ssn':
        return this.maskSSN(data);
      case 'credit_card':
        return this.maskCreditCard(data);
      default:
        return data;
    }
  }

  maskEmail(email) {
    const [local, domain] = email.split('@');
    const maskedLocal = local.charAt(0) + '*'.repeat(local.length - 2) + local.charAt(local.length - 1);
    return `${maskedLocal}@${domain}`;
  }

  maskPhone(phone) {
    return phone.replace(/(\d{3})\d{3}(\d{4})/, '$1-***-$2');
  }

  maskSSN(ssn) {
    return ssn.replace(/(\d{3})\d{2}(\d{4})/, '$1-**-$2');
  }

  maskCreditCard(card) {
    return card.replace(/(\d{4})\d{8}(\d{4})/, '$1-********-$2');
  }

  // Anonymize data
  anonymizeData(data, fields) {
    const anonymized = { ...data };
    
    fields.forEach(field => {
      if (anonymized[field]) {
        anonymized[field] = this.generateHash(anonymized[field]);
      }
    });
    
    return anonymized;
  }

  generateHash(value) {
    return crypto.createHash('sha256').update(value + process.env.ANONYMIZATION_SALT).digest('hex');
  }
}

// Data masking middleware
const maskSensitiveData = (fields) => {
  return (req, res, next) => {
    const maskingService = new DataMaskingService();
    
    // Mask request data
    fields.forEach(field => {
      if (req.body[field]) {
        req.body[field] = maskingService.maskData(req.body[field], field);
      }
    });
    
    // Mask response data
    const originalSend = res.json;
    res.json = function(data) {
      if (Array.isArray(data)) {
        data = data.map(item => {
          fields.forEach(field => {
            if (item[field]) {
              item[field] = maskingService.maskData(item[field], field);
            }
          });
          return item;
        });
      } else if (typeof data === 'object') {
        fields.forEach(field => {
          if (data[field]) {
            data[field] = maskingService.maskData(data[field], field);
          }
        });
      }
      
      originalSend.call(this, data);
    };
    
    next();
  };
};
```

## API Security

### 1. Input Validation & Sanitization

```javascript
// Input Validation Service
const Joi = require('joi');
const xss = require('xss');

class InputValidationService {
  // User input schema
  userSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string()
      .min(8)
      .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])'))
      .required()
      .messages({
        'string.pattern.base': 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'
      }),
    name: Joi.string().min(2).max(50).required(),
    age: Joi.number().integer().min(13).max(120).optional()
  });

  // Product input schema
  productSchema = Joi.object({
    name: Joi.string().min(1).max(100).required(),
    description: Joi.string().max(1000).optional(),
    price: Joi.number().positive().precision(2).required(),
    category: Joi.string().valid('electronics', 'clothing', 'books').required()
  });

  // Validate input
  validate(data, schema) {
    const { error, value } = schema.validate(data, {
      abortEarly: false,
      stripUnknown: true
    });

    if (error) {
      throw new ValidationError(error.details.map(detail => detail.message));
    }

    return value;
  }

  // Sanitize input
  sanitize(data) {
    if (typeof data === 'string') {
      return xss(data, {
        whiteList: {},
        stripIgnoreTag: true,
        stripIgnoreTagBody: ['script']
      });
    }

    if (typeof data === 'object') {
      const sanitized = {};
      for (const [key, value] of Object.entries(data)) {
        sanitized[key] = this.sanitize(value);
      }
      return sanitized;
    }

    return data;
  }

  // Validate file upload
  validateFile(file, allowedTypes, maxSize) {
    if (!file) {
      throw new ValidationError('File is required');
    }

    if (!allowedTypes.includes(file.mimetype)) {
      throw new ValidationError(`File type ${file.mimetype} is not allowed`);
    }

    if (file.size > maxSize) {
      throw new ValidationError(`File size exceeds maximum allowed size of ${maxSize} bytes`);
    }

    return true;
  }
}

// Input validation middleware
const validateInput = (schema) => {
  return (req, res, next) => {
    const validationService = new InputValidationService();
    
    try {
      // Validate and sanitize body
      if (req.body) {
        req.body = validationService.validate(req.body, schema);
        req.body = validationService.sanitize(req.body);
      }
      
      // Validate and sanitize query parameters
      if (req.query) {
        req.query = validationService.sanitize(req.query);
      }
      
      next();
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  };
};

// File upload validation middleware
const validateFileUpload = (allowedTypes, maxSize) => {
  return (req, res, next) => {
    const validationService = new InputValidationService();
    
    try {
      validationService.validateFile(req.file, allowedTypes, maxSize);
      next();
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  };
};
```

### 2. Rate Limiting & DDoS Protection

```javascript
// Advanced Rate Limiting
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('redis');

class SecurityService {
  constructor() {
    this.redisClient = redis.createClient({
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_PORT
    });
  }

  // Create rate limiters
  createRateLimiters() {
    // General API rate limiting
    const apiLimiter = rateLimit({
      store: new RedisStore({
        client: this.redisClient,
        prefix: 'api_limit:'
      }),
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many API requests, please try again later',
      standardHeaders: true,
      legacyHeaders: false,
      skip: (req) => req.path === '/health'
    });

    // Authentication rate limiting
    const authLimiter = rateLimit({
      store: new RedisStore({
        client: this.redisClient,
        prefix: 'auth_limit:'
      }),
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // limit each IP to 5 login attempts per windowMs
      message: 'Too many login attempts, please try again later',
      standardHeaders: true,
      legacyHeaders: false
    });

    // File upload rate limiting
    const uploadLimiter = rateLimit({
      store: new RedisStore({
        client: this.redisClient,
        prefix: 'upload_limit:'
      }),
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 10, // limit each IP to 10 uploads per hour
      message: 'Too many file uploads, please try again later'
    });

    return { apiLimiter, authLimiter, uploadLimiter };
  }

  // DDoS protection middleware
  ddosProtection() {
    return (req, res, next) => {
      const clientIP = req.ip;
      const key = `ddos:${clientIP}`;
      
      this.redisClient.incr(key, (err, count) => {
        if (err) {
          return next();
        }
        
        if (count === 1) {
          this.redisClient.expire(key, 60); // 1 minute window
        }
        
        if (count > 100) { // More than 100 requests per minute
          return res.status(429).json({ error: 'Too many requests' });
        }
        
        next();
      });
    };
  }

  // IP whitelist middleware
  ipWhitelist(allowedIPs) {
    return (req, res, next) => {
      const clientIP = req.ip;
      
      if (!allowedIPs.includes(clientIP)) {
        return res.status(403).json({ error: 'Access denied' });
      }
      
      next();
    };
  }

  // Request size limiting
  requestSizeLimit(maxSize) {
    return (req, res, next) => {
      const contentLength = parseInt(req.headers['content-length'], 10);
      
      if (contentLength > maxSize) {
        return res.status(413).json({ error: 'Request entity too large' });
      }
      
      next();
    };
  }
}

// Apply security middleware
const securityService = new SecurityService();
const { apiLimiter, authLimiter, uploadLimiter } = securityService.createRateLimiters();

app.use('/api/', apiLimiter);
app.use('/auth/', authLimiter);
app.use('/upload/', uploadLimiter);
app.use(securityService.ddosProtection());
app.use(securityService.requestSizeLimit(10 * 1024 * 1024)); // 10MB limit
```

## Infrastructure Security

### 1. Network Security

```javascript
// Security Headers Middleware
const helmet = require('helmet');

// Configure security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'", "https://api.example.com"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// CORS Configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];
    
    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));
```

### 2. Container Security

```dockerfile
# Secure Dockerfile
FROM node:18-alpine AS builder

# Install security updates
RUN apk update && apk upgrade

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY --chown=nodejs:nodejs . .

# Build application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Install security updates
RUN apk update && apk upgrade

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy built application
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package*.json ./

# Create necessary directories with proper permissions
RUN mkdir -p /app/logs && \
    chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start application
CMD ["npm", "start"]
```

## Security Monitoring

### 1. Security Event Logging

```javascript
// Security Logger
class SecurityLogger {
  constructor() {
    this.logger = require('winston').createLogger({
      level: 'info',
      format: require('winston').format.combine(
        require('winston').format.timestamp(),
        require('winston').format.json()
      ),
      transports: [
        new require('winston').transports.File({ filename: 'security.log' }),
        new require('winston').transports.Console()
      ]
    });
  }

  // Log security events
  logSecurityEvent(event) {
    const securityEvent = {
      timestamp: new Date().toISOString(),
      event: event.type,
      severity: event.severity || 'medium',
      user: event.user,
      ip: event.ip,
      userAgent: event.userAgent,
      details: event.details,
      sessionId: event.sessionId
    };

    this.logger.info('Security Event', securityEvent);

    // Send alert for high severity events
    if (event.severity === 'high') {
      this.sendAlert(securityEvent);
    }
  }

  // Log authentication events
  logAuthEvent(userId, event, success, details = {}) {
    this.logSecurityEvent({
      type: 'authentication',
      severity: success ? 'low' : 'medium',
      user: userId,
      ip: details.ip,
      userAgent: details.userAgent,
      details: {
        event,
        success,
        ...details
      }
    });
  }

  // Log authorization events
  logAuthzEvent(userId, resource, action, success, details = {}) {
    this.logSecurityEvent({
      type: 'authorization',
      severity: success ? 'low' : 'high',
      user: userId,
      ip: details.ip,
      userAgent: details.userAgent,
      details: {
        resource,
        action,
        success,
        ...details
      }
    });
  }

  // Log data access events
  logDataAccessEvent(userId, dataType, action, details = {}) {
    this.logSecurityEvent({
      type: 'data_access',
      severity: 'medium',
      user: userId,
      ip: details.ip,
      userAgent: details.userAgent,
      details: {
        dataType,
        action,
        ...details
      }
    });
  }

  // Send security alerts
  async sendAlert(event) {
    // Send email alert
    const nodemailer = require('nodemailer');
    const transporter = nodemailer.createTransporter({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: true,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    await transporter.sendMail({
      from: process.env.FROM_EMAIL,
      to: process.env.SECURITY_ALERT_EMAIL,
      subject: `Security Alert: ${event.event}`,
      html: `
        <h2>Security Alert</h2>
        <p><strong>Event:</strong> ${event.event}</p>
        <p><strong>Severity:</strong> ${event.severity}</p>
        <p><strong>User:</strong> ${event.user}</p>
        <p><strong>IP:</strong> ${event.ip}</p>
        <p><strong>Time:</strong> ${event.timestamp}</p>
        <p><strong>Details:</strong> ${JSON.stringify(event.details, null, 2)}</p>
      `
    });
  }
}

// Security monitoring middleware
const securityLogger = new SecurityLogger();

const logSecurityEvents = (req, res, next) => {
  const originalSend = res.send;
  
  res.send = function(data) {
    // Log failed authentication attempts
    if (req.path.includes('/auth') && res.statusCode === 401) {
      securityLogger.logAuthEvent(
        req.body?.email || 'unknown',
        'login_failed',
        false,
        {
          ip: req.ip,
          userAgent: req.get('User-Agent')
        }
      );
    }
    
    // Log successful authentication
    if (req.path.includes('/auth') && res.statusCode === 200) {
      securityLogger.logAuthEvent(
        req.body?.email || 'unknown',
        'login_success',
        true,
        {
          ip: req.ip,
          userAgent: req.get('User-Agent')
        }
      );
    }
    
    originalSend.call(this, data);
  };
  
  next();
};

app.use(logSecurityEvents);
```

### 2. Intrusion Detection

```javascript
// Intrusion Detection System
class IntrusionDetectionSystem {
  constructor() {
    this.suspiciousPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /union\s+select/gi,
      /drop\s+table/gi,
      /exec\s*\(/gi,
      /eval\s*\(/gi
    ];
    
    this.failedAttempts = new Map();
    this.blockedIPs = new Set();
  }

  // Check for suspicious patterns
  checkSuspiciousPatterns(input) {
    for (const pattern of this.suspiciousPatterns) {
      if (pattern.test(input)) {
        return true;
      }
    }
    return false;
  }

  // Track failed attempts
  trackFailedAttempt(ip, reason) {
    if (!this.failedAttempts.has(ip)) {
      this.failedAttempts.set(ip, []);
    }
    
    const attempts = this.failedAttempts.get(ip);
    attempts.push({
      timestamp: Date.now(),
      reason
    });
    
    // Remove attempts older than 1 hour
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    const recentAttempts = attempts.filter(attempt => attempt.timestamp > oneHourAgo);
    this.failedAttempts.set(ip, recentAttempts);
    
    // Block IP if too many failed attempts
    if (recentAttempts.length >= 10) {
      this.blockedIPs.add(ip);
      securityLogger.logSecurityEvent({
        type: 'ip_blocked',
        severity: 'high',
        ip,
        details: {
          reason: 'too_many_failed_attempts',
          attempts: recentAttempts.length
        }
      });
    }
  }

  // Check if IP is blocked
  isIPBlocked(ip) {
    return this.blockedIPs.has(ip);
  }

  // Unblock IP
  unblockIP(ip) {
    this.blockedIPs.delete(ip);
    this.failedAttempts.delete(ip);
  }
}

// Intrusion detection middleware
const ids = new IntrusionDetectionSystem();

const intrusionDetection = (req, res, next) => {
  const clientIP = req.ip;
  
  // Check if IP is blocked
  if (ids.isIPBlocked(clientIP)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  // Check request body for suspicious patterns
  if (req.body) {
    const bodyString = JSON.stringify(req.body);
    if (ids.checkSuspiciousPatterns(bodyString)) {
      ids.trackFailedAttempt(clientIP, 'suspicious_pattern_detected');
      return res.status(400).json({ error: 'Invalid input detected' });
    }
  }
  
  // Check query parameters for suspicious patterns
  if (req.query) {
    const queryString = JSON.stringify(req.query);
    if (ids.checkSuspiciousPatterns(queryString)) {
      ids.trackFailedAttempt(clientIP, 'suspicious_query_detected');
      return res.status(400).json({ error: 'Invalid query parameters' });
    }
  }
  
  next();
};

app.use(intrusionDetection);
```

## Compliance & Standards

### 1. GDPR Compliance

```javascript
// GDPR Compliance Service
class GDPRComplianceService {
  // Data subject rights
  async handleDataSubjectRequest(userId, requestType, data = {}) {
    switch (requestType) {
      case 'access':
        return await this.provideDataAccess(userId);
      case 'rectification':
        return await this.rectifyData(userId, data);
      case 'erasure':
        return await this.eraseData(userId);
      case 'portability':
        return await this.provideDataPortability(userId);
      case 'restriction':
        return await this.restrictProcessing(userId);
      default:
        throw new Error('Invalid request type');
    }
  }

  // Provide data access
  async provideDataAccess(userId) {
    const userData = await User.findById(userId);
    const userPosts = await Post.find({ author: userId });
    const userComments = await Comment.find({ author: userId });
    
    return {
      personalData: {
        profile: {
          name: userData.name,
          email: userData.email,
          createdAt: userData.createdAt,
          lastLogin: userData.lastLogin
        },
        posts: userPosts.map(post => ({
          title: post.title,
          content: post.content,
          createdAt: post.createdAt
        })),
        comments: userComments.map(comment => ({
          content: comment.content,
          createdAt: comment.createdAt
        }))
      },
      metadata: {
        requestDate: new Date().toISOString(),
        requestType: 'access'
      }
    };
  }

  // Rectify data
  async rectifyData(userId, data) {
    const allowedFields = ['name', 'email', 'profile'];
    const updateData = {};
    
    allowedFields.forEach(field => {
      if (data[field] !== undefined) {
        updateData[field] = data[field];
      }
    });
    
    await User.findByIdAndUpdate(userId, updateData);
    
    // Log the rectification
    securityLogger.logSecurityEvent({
      type: 'data_rectification',
      severity: 'medium',
      user: userId,
      details: {
        fields: Object.keys(updateData),
        timestamp: new Date().toISOString()
      }
    });
    
    return { success: true, message: 'Data rectified successfully' };
  }

  // Erase data (right to be forgotten)
  async eraseData(userId) {
    // Anonymize personal data
    await User.findByIdAndUpdate(userId, {
      name: 'Deleted User',
      email: `deleted_${userId}@deleted.com`,
      isDeleted: true,
      deletedAt: new Date()
    });
    
    // Anonymize posts
    await Post.updateMany(
      { author: userId },
      { 
        content: '[Content deleted]',
        isDeleted: true,
        deletedAt: new Date()
      }
    );
    
    // Anonymize comments
    await Comment.updateMany(
      { author: userId },
      {
        content: '[Comment deleted]',
        isDeleted: true,
        deletedAt: new Date()
      }
    );
    
    // Log the erasure
    securityLogger.logSecurityEvent({
      type: 'data_erasure',
      severity: 'high',
      user: userId,
      details: {
        timestamp: new Date().toISOString()
      }
    });
    
    return { success: true, message: 'Data erased successfully' };
  }

  // Provide data portability
  async provideDataPortability(userId) {
    const data = await this.provideDataAccess(userId);
    
    // Convert to JSON format for portability
    const portableData = {
      format: 'json',
      version: '1.0',
      exportedAt: new Date().toISOString(),
      data: data.personalData
    };
    
    return portableData;
  }

  // Restrict processing
  async restrictProcessing(userId) {
    await User.findByIdAndUpdate(userId, {
      processingRestricted: true,
      restrictionDate: new Date()
    });
    
    // Log the restriction
    securityLogger.logSecurityEvent({
      type: 'processing_restriction',
      severity: 'medium',
      user: userId,
      details: {
        timestamp: new Date().toISOString()
      }
    });
    
    return { success: true, message: 'Processing restricted successfully' };
  }
}

// GDPR compliance middleware
const gdprService = new GDPRComplianceService();

// GDPR routes
app.get('/gdpr/access/:userId', async (req, res) => {
  try {
    const data = await gdprService.handleDataSubjectRequest(req.params.userId, 'access');
    res.json(data);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/gdpr/rectify/:userId', async (req, res) => {
  try {
    const result = await gdprService.handleDataSubjectRequest(req.params.userId, 'rectification', req.body);
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/gdpr/erase/:userId', async (req, res) => {
  try {
    const result = await gdprService.handleDataSubjectRequest(req.params.userId, 'erasure');
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
```

### 2. Security Headers & CSP

```javascript
// Content Security Policy Configuration
const cspConfig = {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      "'unsafe-inline'", // Only if necessary
      "https://cdn.jsdelivr.net",
      "https://www.google-analytics.com"
    ],
    styleSrc: [
      "'self'",
      "'unsafe-inline'",
      "https://fonts.googleapis.com",
      "https://cdn.jsdelivr.net"
    ],
    fontSrc: [
      "'self'",
      "https://fonts.gstatic.com",
      "https://cdn.jsdelivr.net"
    ],
    imgSrc: [
      "'self'",
      "data:",
      "https:",
      "https://www.google-analytics.com"
    ],
    connectSrc: [
      "'self'",
      "https://api.example.com",
      "https://www.google-analytics.com"
    ],
    frameSrc: ["'none'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    manifestSrc: ["'self'"],
    workerSrc: ["'self'"],
    formAction: ["'self'"],
    baseUri: ["'self'"],
    upgradeInsecureRequests: []
  },
  reportOnly: false,
  reportUri: '/csp-report'
};

// CSP Report Handler
app.post('/csp-report', (req, res) => {
  const report = req.body;
  
  securityLogger.logSecurityEvent({
    type: 'csp_violation',
    severity: 'medium',
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    details: {
      violatedDirective: report['csp-report']['violated-directive'],
      blockedUri: report['csp-report']['blocked-uri'],
      documentUri: report['csp-report']['document-uri']
    }
  });
  
  res.status(204).send();
});

// Apply CSP
app.use(helmet.contentSecurityPolicy(cspConfig));
```

This security guide provides comprehensive coverage of modern security practices, including authentication, authorization, data protection, API security, infrastructure security, monitoring, and compliance standards. Each section includes practical implementation examples and best practices for building secure applications.
