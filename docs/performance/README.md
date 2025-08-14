# Performance & Optimization Guide

## Overview
This guide covers performance optimization strategies for building fast, scalable applications. It includes performance metrics, optimization techniques, caching strategies, and load balancing.

## Table of Contents
1. [Performance Metrics](#performance-metrics)
2. [Frontend Optimization](#frontend-optimization)
3. [Backend Optimization](#backend-optimization)
4. [Database Optimization](#database-optimization)
5. [Caching Strategies](#caching-strategies)
6. [Load Balancing](#load-balancing)
7. [Monitoring & Profiling](#monitoring--profiling)

## Performance Metrics

### 1. Core Web Vitals

```javascript
// Performance Monitoring
class PerformanceMonitor {
  constructor() {
    this.metrics = {};
    this.initObservers();
  }

  initObservers() {
    // Largest Contentful Paint (LCP)
    new PerformanceObserver((list) => {
      const entries = list.getEntries();
      const lastEntry = entries[entries.length - 1];
      this.metrics.lcp = lastEntry.startTime;
      this.reportMetric('LCP', lastEntry.startTime);
    }).observe({ entryTypes: ['largest-contentful-paint'] });

    // First Input Delay (FID)
    new PerformanceObserver((list) => {
      const entries = list.getEntries();
      entries.forEach((entry) => {
        this.metrics.fid = entry.processingStart - entry.startTime;
        this.reportMetric('FID', this.metrics.fid);
      });
    }).observe({ entryTypes: ['first-input'] });

    // Cumulative Layout Shift (CLS)
    new PerformanceObserver((list) => {
      let clsValue = 0;
      const entries = list.getEntries();
      entries.forEach((entry) => {
        if (!entry.hadRecentInput) {
          clsValue += entry.value;
        }
      });
      this.metrics.cls = clsValue;
      this.reportMetric('CLS', clsValue);
    }).observe({ entryTypes: ['layout-shift'] });
  }

  reportMetric(name, value) {
    // Send to analytics
    if (window.gtag) {
      window.gtag('event', name, {
        value: Math.round(value),
        custom_parameter: 'performance'
      });
    }
  }

  getMetrics() {
    return this.metrics;
  }
}
```

### 2. API Performance Metrics

```javascript
// API Performance Monitoring
const performanceMiddleware = (req, res, next) => {
  const start = process.hrtime.bigint();
  
  res.on('finish', () => {
    const end = process.hrtime.bigint();
    const duration = Number(end - start) / 1000000; // Convert to milliseconds
    
    const metrics = {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration,
      timestamp: new Date().toISOString(),
      userAgent: req.get('User-Agent'),
      ip: req.ip
    };
    
    // Log slow requests
    if (duration > 1000) {
      console.warn('Slow request detected:', metrics);
    }
    
    // Send to monitoring service
    this.sendToMonitoring(metrics);
  });
  
  next();
};
```

## Frontend Optimization

### 1. Code Splitting

```javascript
// React Code Splitting
import React, { lazy, Suspense } from 'react';

// Lazy load components
const Dashboard = lazy(() => import('./components/Dashboard'));
const UserProfile = lazy(() => import('./components/UserProfile'));
const Settings = lazy(() => import('./components/Settings'));

// Route-based code splitting
const App = () => {
  return (
    <Router>
      <Suspense fallback={<LoadingSpinner />}>
        <Switch>
          <Route path="/dashboard" component={Dashboard} />
          <Route path="/profile" component={UserProfile} />
          <Route path="/settings" component={Settings} />
        </Switch>
      </Suspense>
    </Router>
  );
};

// Dynamic imports for conditional loading
const loadFeature = async (featureName) => {
  switch (featureName) {
    case 'analytics':
      return await import('./features/analytics');
    case 'chat':
      return await import('./features/chat');
    default:
      throw new Error(`Unknown feature: ${featureName}`);
  }
};
```

### 2. Image Optimization

```javascript
// Image Optimization Component
import React from 'react';

const OptimizedImage = ({ src, alt, sizes, ...props }) => {
  const [imageSrc, setImageSrc] = React.useState(null);
  const [isLoaded, setIsLoaded] = React.useState(false);

  React.useEffect(() => {
    const img = new Image();
    img.onload = () => {
      setImageSrc(src);
      setIsLoaded(true);
    };
    img.src = src;
  }, [src]);

  return (
    <div className="image-container">
      {!isLoaded && <div className="image-placeholder" />}
      <img
        src={imageSrc}
        alt={alt}
        sizes={sizes}
        loading="lazy"
        onLoad={() => setIsLoaded(true)}
        {...props}
      />
    </div>
  );
};

// WebP support detection
const supportsWebP = () => {
  return new Promise((resolve) => {
    const webP = new Image();
    webP.onload = webP.onerror = () => {
      resolve(webP.height === 2);
    };
    webP.src = 'data:image/webp;base64,UklGRjoAAABXRUJQVlA4IC4AAACyAgCdASoCAAIALmk0mk0iIiIiIgBoSygABc6WWgAA/veff/0PP8bA//LwYAAA';
  });
};
```

## Backend Optimization

### 1. Response Compression

```javascript
// Compression Middleware
const compression = require('compression');

const compressionOptions = {
  filter: (req, res) => {
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  },
  level: 6,
  threshold: 1024,
  windowBits: 15
};

app.use(compression(compressionOptions));

// Gzip compression for specific routes
app.get('/api/large-data', compression(), (req, res) => {
  // Return large dataset
  res.json(largeDataset);
});
```

### 2. Connection Pooling

```javascript
// Database Connection Pool
const { Pool } = require('pg');

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  statement_timeout: 30000,
  query_timeout: 30000
});

// Connection pool monitoring
pool.on('connect', (client) => {
  console.log('New client connected to database');
});

pool.on('error', (err, client) => {
  console.error('Unexpected error on idle client', err);
});

// Optimized query execution
const executeQuery = async (query, params) => {
  const client = await pool.connect();
  try {
    const result = await client.query(query, params);
    return result.rows;
  } finally {
    client.release();
  }
};
```

## Database Optimization

### 1. Query Optimization

```sql
-- Index optimization
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_posts_author_created ON posts(author_id, created_at DESC);
CREATE INDEX CONCURRENTLY idx_comments_post_created ON comments(post_id, created_at DESC);

-- Composite indexes for complex queries
CREATE INDEX CONCURRENTLY idx_orders_user_status_date 
ON orders(user_id, status, created_at DESC);

-- Partial indexes for filtered queries
CREATE INDEX CONCURRENTLY idx_active_users 
ON users(email) WHERE is_active = true;

-- Query optimization examples
-- Before: N+1 query problem
SELECT * FROM posts WHERE author_id = 1;
SELECT * FROM users WHERE id = 1;

-- After: Single optimized query
SELECT p.*, u.name as author_name, u.email as author_email
FROM posts p
JOIN users u ON p.author_id = u.id
WHERE p.author_id = 1;

-- Pagination optimization
SELECT p.*, u.name as author_name
FROM posts p
JOIN users u ON p.author_id = u.id
WHERE p.created_at < '2024-01-01'
ORDER BY p.created_at DESC
LIMIT 20 OFFSET 40;
```

### 2. Database Partitioning

```sql
-- Table partitioning by date
CREATE TABLE posts (
    id SERIAL,
    title VARCHAR(255),
    content TEXT,
    author_id INTEGER,
    created_at TIMESTAMP
) PARTITION BY RANGE (created_at);

-- Create partitions
CREATE TABLE posts_2024_01 PARTITION OF posts
FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

CREATE TABLE posts_2024_02 PARTITION OF posts
FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');

-- Automatic partition creation
CREATE OR REPLACE FUNCTION create_monthly_partition()
RETURNS TRIGGER AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    partition_name := 'posts_' || to_char(NEW.created_at, 'YYYY_MM');
    start_date := date_trunc('month', NEW.created_at);
    end_date := start_date + interval '1 month';
    
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name = partition_name
    ) THEN
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF posts FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER create_partition_trigger
    BEFORE INSERT ON posts
    FOR EACH ROW
    EXECUTE FUNCTION create_monthly_partition();
```

## Caching Strategies

### 1. Redis Caching

```javascript
// Redis Cache Service
const redis = require('redis');

class CacheService {
  constructor() {
    this.client = redis.createClient({
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_PORT,
      retry_strategy: (options) => {
        if (options.error && options.error.code === 'ECONNREFUSED') {
          return new Error('The server refused the connection');
        }
        if (options.total_retry_time > 1000 * 60 * 60) {
          return new Error('Retry time exhausted');
        }
        if (options.attempt > 10) {
          return undefined;
        }
        return Math.min(options.attempt * 100, 3000);
      }
    });
  }

  async get(key) {
    try {
      const value = await this.client.get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  }

  async set(key, value, ttl = 3600) {
    try {
      await this.client.setex(key, ttl, JSON.stringify(value));
    } catch (error) {
      console.error('Cache set error:', error);
    }
  }

  async del(key) {
    try {
      await this.client.del(key);
    } catch (error) {
      console.error('Cache delete error:', error);
    }
  }

  async invalidatePattern(pattern) {
    try {
      const keys = await this.client.keys(pattern);
      if (keys.length > 0) {
        await this.client.del(keys);
      }
    } catch (error) {
      console.error('Cache pattern invalidation error:', error);
    }
  }
}

// Cache middleware
const cacheMiddleware = (ttl = 300) => {
  return async (req, res, next) => {
    const cacheKey = `cache:${req.originalUrl}`;
    const cacheService = new CacheService();
    
    try {
      const cached = await cacheService.get(cacheKey);
      if (cached) {
        return res.json(cached);
      }
      
      res.sendResponse = res.json;
      res.json = (body) => {
        cacheService.set(cacheKey, body, ttl);
        res.sendResponse(body);
      };
      
      next();
    } catch (error) {
      next();
    }
  };
};
```

### 2. Application-Level Caching

```javascript
// In-Memory Cache
class MemoryCache {
  constructor() {
    this.cache = new Map();
    this.ttl = new Map();
  }

  set(key, value, ttlSeconds = 300) {
    this.cache.set(key, value);
    this.ttl.set(key, Date.now() + (ttlSeconds * 1000));
  }

  get(key) {
    if (!this.cache.has(key)) {
      return null;
    }
    
    if (Date.now() > this.ttl.get(key)) {
      this.delete(key);
      return null;
    }
    
    return this.cache.get(key);
  }

  delete(key) {
    this.cache.delete(key);
    this.ttl.delete(key);
  }

  clear() {
    this.cache.clear();
    this.ttl.clear();
  }
}

// Cache decorator
const cache = (ttl = 300) => {
  return (target, propertyKey, descriptor) => {
    const method = descriptor.value;
    const cacheInstance = new MemoryCache();
    
    descriptor.value = async function (...args) {
      const cacheKey = `${propertyKey}:${JSON.stringify(args)}`;
      const cached = cacheInstance.get(cacheKey);
      
      if (cached) {
        return cached;
      }
      
      const result = await method.apply(this, args);
      cacheInstance.set(cacheKey, result, ttl);
      return result;
    };
    
    return descriptor;
  };
};

// Usage example
class UserService {
  @cache(600) // Cache for 10 minutes
  async getUserById(id) {
    return await User.findByPk(id);
  }
}
```

## Load Balancing

### 1. Nginx Load Balancer

```nginx
# nginx.conf
upstream backend {
    least_conn;  # Least connections algorithm
    server backend1.example.com:3000 weight=3 max_fails=3 fail_timeout=30s;
    server backend2.example.com:3000 weight=3 max_fails=3 fail_timeout=30s;
    server backend3.example.com:3000 weight=3 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

server {
    listen 80;
    server_name example.com;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
    
    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Health checks
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }
    
    # Static file serving
    location /static/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        root /var/www/static;
    }
}
```

### 2. Application Load Balancing

```javascript
// Load Balancer Service
class LoadBalancer {
  constructor(servers) {
    this.servers = servers;
    this.currentIndex = 0;
    this.healthChecks = new Map();
  }

  // Round-robin algorithm
  getNextServer() {
    const server = this.servers[this.currentIndex];
    this.currentIndex = (this.currentIndex + 1) % this.servers.length;
    return server;
  }

  // Least connections algorithm
  getLeastConnectionsServer() {
    return this.servers.reduce((min, server) => 
      server.connections < min.connections ? server : min
    );
  }

  // Health check
  async checkHealth(server) {
    try {
      const response = await fetch(`${server.url}/health`, {
        timeout: 5000
      });
      return response.ok;
    } catch (error) {
      return false;
    }
  }

  // Remove unhealthy servers
  async removeUnhealthyServers() {
    for (const server of this.servers) {
      const isHealthy = await this.checkHealth(server);
      if (!isHealthy) {
        this.servers = this.servers.filter(s => s !== server);
        console.log(`Removed unhealthy server: ${server.url}`);
      }
    }
  }
}
```

## Monitoring & Profiling

### 1. Performance Monitoring

```javascript
// Performance Monitoring Service
class PerformanceMonitor {
  constructor() {
    this.metrics = new Map();
    this.startTime = Date.now();
  }

  // Measure function execution time
  measureFunction(name, fn) {
    return async (...args) => {
      const start = process.hrtime.bigint();
      try {
        const result = await fn(...args);
        const end = process.hrtime.bigint();
        const duration = Number(end - start) / 1000000;
        
        this.recordMetric(name, duration);
        return result;
      } catch (error) {
        this.recordError(name, error);
        throw error;
      }
    };
  }

  // Record performance metric
  recordMetric(name, value) {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }
    this.metrics.get(name).push({
      value,
      timestamp: Date.now()
    });
  }

  // Get performance statistics
  getStats(name) {
    const values = this.metrics.get(name) || [];
    if (values.length === 0) return null;
    
    const sorted = values.map(v => v.value).sort((a, b) => a - b);
    return {
      count: sorted.length,
      min: sorted[0],
      max: sorted[sorted.length - 1],
      avg: sorted.reduce((a, b) => a + b, 0) / sorted.length,
      p95: sorted[Math.floor(sorted.length * 0.95)],
      p99: sorted[Math.floor(sorted.length * 0.99)]
    };
  }

  // Generate performance report
  generateReport() {
    const report = {
      uptime: Date.now() - this.startTime,
      metrics: {}
    };
    
    for (const [name, values] of this.metrics) {
      report.metrics[name] = this.getStats(name);
    }
    
    return report;
  }
}

// Usage
const monitor = new PerformanceMonitor();

const optimizedFunction = monitor.measureFunction('database-query', async (id) => {
  return await User.findByPk(id);
});
```

This performance and optimization guide provides comprehensive coverage of modern performance practices, including metrics, optimization techniques, caching strategies, and load balancing. Each section includes practical examples and best practices for building fast and scalable applications.
