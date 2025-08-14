# Testing Guide

## Overview
This guide covers comprehensive testing strategies for building reliable and maintainable applications. It includes unit testing, integration testing, end-to-end testing, and testing best practices.

## Table of Contents
1. [Testing Strategy](#testing-strategy)
2. [Unit Testing](#unit-testing)
3. [Integration Testing](#integration-testing)
4. [End-to-End Testing](#end-to-end-testing)
5. [Performance Testing](#performance-testing)
6. [Security Testing](#security-testing)
7. [Test Automation](#test-automation)

## Testing Strategy

### 1. Testing Pyramid

```javascript
// Testing Pyramid Configuration
const testingPyramid = {
  unit: {
    percentage: 70,
    tools: ['Jest', 'Mocha', 'Vitest'],
    scope: 'Individual functions and components',
    speed: 'Fast',
    cost: 'Low'
  },
  integration: {
    percentage: 20,
    tools: ['Supertest', 'Jest', 'TestContainers'],
    scope: 'API endpoints and database interactions',
    speed: 'Medium',
    cost: 'Medium'
  },
  e2e: {
    percentage: 10,
    tools: ['Cypress', 'Playwright', 'Selenium'],
    scope: 'Complete user workflows',
    speed: 'Slow',
    cost: 'High'
  }
};
```

### 2. Test Environment Setup

```javascript
// Test Configuration
const testConfig = {
  // Unit test configuration
  unit: {
    testEnvironment: 'node',
    collectCoverage: true,
    coverageThreshold: {
      global: {
        branches: 80,
        functions: 80,
        lines: 80,
        statements: 80
      }
    },
    setupFilesAfterEnv: ['<rootDir>/tests/setup/unit.js']
  },
  
  // Integration test configuration
  integration: {
    testEnvironment: 'node',
    setupFilesAfterEnv: ['<rootDir>/tests/setup/integration.js'],
    testTimeout: 10000
  },
  
  // E2E test configuration
  e2e: {
    baseUrl: 'http://localhost:3000',
    viewportWidth: 1280,
    viewportHeight: 720,
    video: true,
    screenshot: true
  }
};
```

## Unit Testing

### 1. Jest Configuration

```javascript
// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: [
    '**/__tests__/**/*.+(ts|tsx|js)',
    '**/*.(test|spec).+(ts|tsx|js)'
  ],
  transform: {
    '^.+\\.(ts|tsx)$': 'ts-jest'
  },
  collectCoverageFrom: [
    'src/**/*.{js,ts}',
    '!src/**/*.d.ts',
    '!src/index.ts'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  setupFilesAfterEnv: ['<rootDir>/tests/setup/jest.js'],
  testTimeout: 10000,
  verbose: true
};
```

### 2. Unit Test Examples

```javascript
// User Service Tests
import { UserService } from '../src/services/UserService';
import { User } from '../src/models/User';

// Mock the User model
jest.mock('../src/models/User');

describe('UserService', () => {
  let userService;
  let mockUser;

  beforeEach(() => {
    userService = new UserService();
    mockUser = {
      id: 1,
      email: 'test@example.com',
      name: 'Test User',
      isActive: true
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createUser', () => {
    it('should create a new user successfully', async () => {
      // Arrange
      const userData = {
        email: 'new@example.com',
        name: 'New User',
        password: 'password123'
      };
      
      User.create.mockResolvedValue(mockUser);

      // Act
      const result = await userService.createUser(userData);

      // Assert
      expect(User.create).toHaveBeenCalledWith(userData);
      expect(result).toEqual(mockUser);
    });

    it('should throw error if email already exists', async () => {
      // Arrange
      const userData = {
        email: 'existing@example.com',
        name: 'Existing User',
        password: 'password123'
      };
      
      User.create.mockRejectedValue(new Error('Email already exists'));

      // Act & Assert
      await expect(userService.createUser(userData))
        .rejects
        .toThrow('Email already exists');
    });
  });

  describe('getUserById', () => {
    it('should return user if found', async () => {
      // Arrange
      const userId = 1;
      User.findByPk.mockResolvedValue(mockUser);

      // Act
      const result = await userService.getUserById(userId);

      // Assert
      expect(User.findByPk).toHaveBeenCalledWith(userId);
      expect(result).toEqual(mockUser);
    });

    it('should return null if user not found', async () => {
      // Arrange
      const userId = 999;
      User.findByPk.mockResolvedValue(null);

      // Act
      const result = await userService.getUserById(userId);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('updateUser', () => {
    it('should update user successfully', async () => {
      // Arrange
      const userId = 1;
      const updateData = { name: 'Updated Name' };
      const updatedUser = { ...mockUser, ...updateData };
      
      User.findByPk.mockResolvedValue(mockUser);
      mockUser.update = jest.fn().mockResolvedValue(updatedUser);

      // Act
      const result = await userService.updateUser(userId, updateData);

      // Assert
      expect(mockUser.update).toHaveBeenCalledWith(updateData);
      expect(result).toEqual(updatedUser);
    });

    it('should throw error if user not found', async () => {
      // Arrange
      const userId = 999;
      const updateData = { name: 'Updated Name' };
      User.findByPk.mockResolvedValue(null);

      // Act & Assert
      await expect(userService.updateUser(userId, updateData))
        .rejects
        .toThrow('User not found');
    });
  });
});
```

### 3. Component Testing (React)

```javascript
// UserProfile Component Tests
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import UserProfile from '../src/components/UserProfile';

// Mock the API service
jest.mock('../src/services/api');

const renderWithRouter = (component) => {
  return render(
    <BrowserRouter>
      {component}
    </BrowserRouter>
  );
};

describe('UserProfile', () => {
  const mockUser = {
    id: 1,
    name: 'John Doe',
    email: 'john@example.com',
    avatar: 'https://example.com/avatar.jpg'
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should render user profile correctly', () => {
    // Arrange & Act
    renderWithRouter(<UserProfile user={mockUser} />);

    // Assert
    expect(screen.getByText('John Doe')).toBeInTheDocument();
    expect(screen.getByText('john@example.com')).toBeInTheDocument();
    expect(screen.getByAltText('User avatar')).toHaveAttribute('src', mockUser.avatar);
  });

  it('should show edit form when edit button is clicked', () => {
    // Arrange
    renderWithRouter(<UserProfile user={mockUser} />);

    // Act
    fireEvent.click(screen.getByText('Edit Profile'));

    // Assert
    expect(screen.getByLabelText('Name')).toBeInTheDocument();
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
    expect(screen.getByText('Save')).toBeInTheDocument();
  });

  it('should update user profile when form is submitted', async () => {
    // Arrange
    const mockUpdateUser = jest.fn().mockResolvedValue({ ...mockUser, name: 'Jane Doe' });
    jest.spyOn(require('../src/services/api'), 'updateUser').mockImplementation(mockUpdateUser);
    
    renderWithRouter(<UserProfile user={mockUser} />);

    // Act
    fireEvent.click(screen.getByText('Edit Profile'));
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Jane Doe' } });
    fireEvent.click(screen.getByText('Save'));

    // Assert
    await waitFor(() => {
      expect(mockUpdateUser).toHaveBeenCalledWith(1, { name: 'Jane Doe' });
      expect(screen.getByText('Jane Doe')).toBeInTheDocument();
    });
  });

  it('should show error message when update fails', async () => {
    // Arrange
    const mockUpdateUser = jest.fn().mockRejectedValue(new Error('Update failed'));
    jest.spyOn(require('../src/services/api'), 'updateUser').mockImplementation(mockUpdateUser);
    
    renderWithRouter(<UserProfile user={mockUser} />);

    // Act
    fireEvent.click(screen.getByText('Edit Profile'));
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Jane Doe' } });
    fireEvent.click(screen.getByText('Save'));

    // Assert
    await waitFor(() => {
      expect(screen.getByText('Failed to update profile')).toBeInTheDocument();
    });
  });
});
```

## Integration Testing

### 1. API Integration Tests

```javascript
// API Integration Tests
import request from 'supertest';
import app from '../src/app';
import { sequelize } from '../src/models';
import { User } from '../src/models';

describe('User API', () => {
  beforeAll(async () => {
    await sequelize.sync({ force: true });
  });

  afterAll(async () => {
    await sequelize.close();
  });

  beforeEach(async () => {
    await User.destroy({ where: {} });
  });

  describe('POST /api/users', () => {
    it('should create a new user', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        name: 'Test User',
        password: 'password123'
      };

      // Act
      const response = await request(app)
        .post('/api/users')
        .send(userData)
        .expect(201);

      // Assert
      expect(response.body).toHaveProperty('id');
      expect(response.body.email).toBe(userData.email);
      expect(response.body.name).toBe(userData.name);
      expect(response.body).not.toHaveProperty('password');

      // Verify in database
      const user = await User.findByPk(response.body.id);
      expect(user).toBeTruthy();
      expect(user.email).toBe(userData.email);
    });

    it('should return 400 for invalid email', async () => {
      // Arrange
      const userData = {
        email: 'invalid-email',
        name: 'Test User',
        password: 'password123'
      };

      // Act & Assert
      await request(app)
        .post('/api/users')
        .send(userData)
        .expect(400);
    });

    it('should return 400 for duplicate email', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        name: 'Test User',
        password: 'password123'
      };

      await User.create(userData);

      // Act & Assert
      await request(app)
        .post('/api/users')
        .send(userData)
        .expect(400);
    });
  });

  describe('GET /api/users/:id', () => {
    it('should return user by id', async () => {
      // Arrange
      const user = await User.create({
        email: 'test@example.com',
        name: 'Test User',
        password: 'password123'
      });

      // Act
      const response = await request(app)
        .get(`/api/users/${user.id}`)
        .expect(200);

      // Assert
      expect(response.body.id).toBe(user.id);
      expect(response.body.email).toBe(user.email);
      expect(response.body.name).toBe(user.name);
    });

    it('should return 404 for non-existent user', async () => {
      // Act & Assert
      await request(app)
        .get('/api/users/999')
        .expect(404);
    });
  });

  describe('PUT /api/users/:id', () => {
    it('should update user successfully', async () => {
      // Arrange
      const user = await User.create({
        email: 'test@example.com',
        name: 'Test User',
        password: 'password123'
      });

      const updateData = {
        name: 'Updated Name',
        email: 'updated@example.com'
      };

      // Act
      const response = await request(app)
        .put(`/api/users/${user.id}`)
        .send(updateData)
        .expect(200);

      // Assert
      expect(response.body.name).toBe(updateData.name);
      expect(response.body.email).toBe(updateData.email);

      // Verify in database
      const updatedUser = await User.findByPk(user.id);
      expect(updatedUser.name).toBe(updateData.name);
      expect(updatedUser.email).toBe(updateData.email);
    });
  });

  describe('DELETE /api/users/:id', () => {
    it('should delete user successfully', async () => {
      // Arrange
      const user = await User.create({
        email: 'test@example.com',
        name: 'Test User',
        password: 'password123'
      });

      // Act
      await request(app)
        .delete(`/api/users/${user.id}`)
        .expect(204);

      // Assert
      const deletedUser = await User.findByPk(user.id);
      expect(deletedUser).toBeNull();
    });
  });
});
```

### 2. Database Integration Tests

```javascript
// Database Integration Tests
import { sequelize, User, Post } from '../src/models';

describe('Database Integration', () => {
  beforeAll(async () => {
    await sequelize.sync({ force: true });
  });

  afterAll(async () => {
    await sequelize.close();
  });

  beforeEach(async () => {
    await User.destroy({ where: {} });
    await Post.destroy({ where: {} });
  });

  describe('User-Post Relationship', () => {
    it('should create user with posts', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        name: 'Test User',
        password: 'password123'
      };

      const postData = [
        { title: 'First Post', content: 'Content 1' },
        { title: 'Second Post', content: 'Content 2' }
      ];

      // Act
      const user = await User.create(userData);
      const posts = await Promise.all(
        postData.map(post => Post.create({ ...post, authorId: user.id }))
      );

      // Assert
      expect(user.id).toBeDefined();
      expect(posts).toHaveLength(2);
      expect(posts[0].authorId).toBe(user.id);
      expect(posts[1].authorId).toBe(user.id);
    });

    it('should load user with posts', async () => {
      // Arrange
      const user = await User.create({
        email: 'test@example.com',
        name: 'Test User',
        password: 'password123'
      });

      await Post.create({
        title: 'Test Post',
        content: 'Test Content',
        authorId: user.id
      });

      // Act
      const userWithPosts = await User.findByPk(user.id, {
        include: [Post]
      });

      // Assert
      expect(userWithPosts.Posts).toHaveLength(1);
      expect(userWithPosts.Posts[0].title).toBe('Test Post');
    });

    it('should cascade delete posts when user is deleted', async () => {
      // Arrange
      const user = await User.create({
        email: 'test@example.com',
        name: 'Test User',
        password: 'password123'
      });

      await Post.create({
        title: 'Test Post',
        content: 'Test Content',
        authorId: user.id
      });

      // Act
      await user.destroy();

      // Assert
      const posts = await Post.findAll({ where: { authorId: user.id } });
      expect(posts).toHaveLength(0);
    });
  });

  describe('Database Transactions', () => {
    it('should rollback transaction on error', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        name: 'Test User',
        password: 'password123'
      };

      // Act & Assert
      await expect(async () => {
        await sequelize.transaction(async (t) => {
          const user = await User.create(userData, { transaction: t });
          await Post.create({
            title: 'Test Post',
            content: 'Test Content',
            authorId: user.id
          }, { transaction: t });

          // Simulate error
          throw new Error('Transaction error');
        });
      }).rejects.toThrow('Transaction error');

      // Verify rollback
      const users = await User.findAll();
      const posts = await Post.findAll();
      expect(users).toHaveLength(0);
      expect(posts).toHaveLength(0);
    });
  });
});
```

## End-to-End Testing

### 1. Cypress Configuration

```javascript
// cypress.config.js
const { defineConfig } = require('cypress');

module.exports = defineConfig({
  e2e: {
    baseUrl: 'http://localhost:3000',
    viewportWidth: 1280,
    viewportHeight: 720,
    video: true,
    screenshot: true,
    defaultCommandTimeout: 10000,
    requestTimeout: 10000,
    responseTimeout: 10000,
    setupNodeEvents(on, config) {
      // implement node event listeners here
    },
  },
  component: {
    devServer: {
      framework: 'react',
      bundler: 'vite',
    },
  },
});
```

### 2. E2E Test Examples

```javascript
// User Registration and Login E2E Tests
describe('User Authentication', () => {
  beforeEach(() => {
    cy.visit('/');
  });

  it('should register a new user successfully', () => {
    // Arrange
    const userData = {
      name: 'Test User',
      email: `test${Date.now()}@example.com`,
      password: 'Password123!'
    };

    // Act
    cy.visit('/register');
    cy.get('[data-testid="name-input"]').type(userData.name);
    cy.get('[data-testid="email-input"]').type(userData.email);
    cy.get('[data-testid="password-input"]').type(userData.password);
    cy.get('[data-testid="confirm-password-input"]').type(userData.password);
    cy.get('[data-testid="register-button"]').click();

    // Assert
    cy.url().should('include', '/dashboard');
    cy.get('[data-testid="user-name"]').should('contain', userData.name);
    cy.get('[data-testid="welcome-message"]').should('be.visible');
  });

  it('should login existing user successfully', () => {
    // Arrange
    const userData = {
      email: 'existing@example.com',
      password: 'Password123!'
    };

    // Act
    cy.visit('/login');
    cy.get('[data-testid="email-input"]').type(userData.email);
    cy.get('[data-testid="password-input"]').type(userData.password);
    cy.get('[data-testid="login-button"]').click();

    // Assert
    cy.url().should('include', '/dashboard');
    cy.get('[data-testid="user-menu"]').should('be.visible');
  });

  it('should show error for invalid credentials', () => {
    // Arrange
    const invalidData = {
      email: 'invalid@example.com',
      password: 'wrongpassword'
    };

    // Act
    cy.visit('/login');
    cy.get('[data-testid="email-input"]').type(invalidData.email);
    cy.get('[data-testid="password-input"]').type(invalidData.password);
    cy.get('[data-testid="login-button"]').click();

    // Assert
    cy.get('[data-testid="error-message"]')
      .should('be.visible')
      .and('contain', 'Invalid credentials');
    cy.url().should('include', '/login');
  });

  it('should logout user successfully', () => {
    // Arrange - Login first
    cy.login('existing@example.com', 'Password123!');

    // Act
    cy.get('[data-testid="user-menu"]').click();
    cy.get('[data-testid="logout-button"]').click();

    // Assert
    cy.url().should('include', '/login');
    cy.get('[data-testid="login-form"]').should('be.visible');
  });
});

// User Profile Management E2E Tests
describe('User Profile Management', () => {
  beforeEach(() => {
    cy.login('existing@example.com', 'Password123!');
  });

  it('should update user profile successfully', () => {
    // Arrange
    const updatedData = {
      name: 'Updated Name',
      bio: 'Updated bio information'
    };

    // Act
    cy.visit('/profile');
    cy.get('[data-testid="edit-profile-button"]').click();
    cy.get('[data-testid="name-input"]').clear().type(updatedData.name);
    cy.get('[data-testid="bio-input"]').clear().type(updatedData.bio);
    cy.get('[data-testid="save-profile-button"]').click();

    // Assert
    cy.get('[data-testid="success-message"]')
      .should('be.visible')
      .and('contain', 'Profile updated successfully');
    cy.get('[data-testid="user-name"]').should('contain', updatedData.name);
    cy.get('[data-testid="user-bio"]').should('contain', updatedData.bio);
  });

  it('should upload profile picture', () => {
    // Arrange
    const imagePath = 'cypress/fixtures/profile-picture.jpg';

    // Act
    cy.visit('/profile');
    cy.get('[data-testid="edit-profile-button"]').click();
    cy.get('[data-testid="profile-picture-input"]').attachFile(imagePath);
    cy.get('[data-testid="save-profile-button"]').click();

    // Assert
    cy.get('[data-testid="success-message"]')
      .should('be.visible')
      .and('contain', 'Profile picture updated');
    cy.get('[data-testid="profile-picture"]')
      .should('be.visible')
      .and('have.attr', 'src')
      .and('not.include', 'default-avatar');
  });
});

// Post Management E2E Tests
describe('Post Management', () => {
  beforeEach(() => {
    cy.login('existing@example.com', 'Password123!');
  });

  it('should create a new post', () => {
    // Arrange
    const postData = {
      title: 'Test Post Title',
      content: 'This is the content of the test post.'
    };

    // Act
    cy.visit('/posts/new');
    cy.get('[data-testid="post-title-input"]').type(postData.title);
    cy.get('[data-testid="post-content-input"]').type(postData.content);
    cy.get('[data-testid="publish-post-button"]').click();

    // Assert
    cy.url().should('include', '/posts/');
    cy.get('[data-testid="post-title"]').should('contain', postData.title);
    cy.get('[data-testid="post-content"]').should('contain', postData.content);
    cy.get('[data-testid="author-name"]').should('contain', 'Test User');
  });

  it('should edit existing post', () => {
    // Arrange
    const updatedData = {
      title: 'Updated Post Title',
      content: 'Updated post content.'
    };

    // Act
    cy.visit('/posts/1');
    cy.get('[data-testid="edit-post-button"]').click();
    cy.get('[data-testid="post-title-input"]').clear().type(updatedData.title);
    cy.get('[data-testid="post-content-input"]').clear().type(updatedData.content);
    cy.get('[data-testid="save-post-button"]').click();

    // Assert
    cy.get('[data-testid="success-message"]')
      .should('be.visible')
      .and('contain', 'Post updated successfully');
    cy.get('[data-testid="post-title"]').should('contain', updatedData.title);
    cy.get('[data-testid="post-content"]').should('contain', updatedData.content);
  });

  it('should delete post with confirmation', () => {
    // Act
    cy.visit('/posts/1');
    cy.get('[data-testid="delete-post-button"]').click();
    cy.get('[data-testid="confirm-delete-button"]').click();

    // Assert
    cy.url().should('include', '/posts');
    cy.get('[data-testid="posts-list"]').should('not.contain', 'Test Post Title');
  });
});
```

## Performance Testing

### 1. Load Testing with Artillery

```javascript
// artillery.config.yml
config:
  target: 'http://localhost:3000'
  phases:
    - duration: 60
      arrivalRate: 10
      name: "Warm up"
    - duration: 300
      arrivalRate: 50
      name: "Sustained load"
    - duration: 60
      arrivalRate: 100
      name: "Peak load"
  defaults:
    headers:
      Content-Type: 'application/json'

scenarios:
  - name: "User registration flow"
    weight: 30
    flow:
      - post:
          url: "/api/users"
          json:
            name: "{{ $randomString() }}"
            email: "{{ $randomEmail() }}"
            password: "Password123!"
          capture:
            - json: "$.id"
              as: "userId"
      - get:
          url: "/api/users/{{ userId }}"
          expect:
            - statusCode: 200

  - name: "User login flow"
    weight: 40
    flow:
      - post:
          url: "/api/auth/login"
          json:
            email: "{{ $randomString() }}@example.com"
            password: "Password123!"
          capture:
            - json: "$.token"
              as: "authToken"
      - get:
          url: "/api/users/me"
          headers:
            Authorization: "Bearer {{ authToken }}"
          expect:
            - statusCode: 200

  - name: "Post creation flow"
    weight: 30
    flow:
      - post:
          url: "/api/auth/login"
          json:
            email: "{{ $randomString() }}@example.com"
            password: "Password123!"
          capture:
            - json: "$.token"
              as: "authToken"
      - post:
          url: "/api/posts"
          headers:
            Authorization: "Bearer {{ authToken }}"
          json:
            title: "{{ $randomString() }}"
            content: "{{ $randomString() }}"
          expect:
            - statusCode: 201
```

### 2. Performance Test Scripts

```javascript
// Performance test with k6
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '2m', target: 100 }, // Ramp up
    { duration: '5m', target: 100 }, // Stay at 100 users
    { duration: '2m', target: 0 },   // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests must complete below 500ms
    http_req_failed: ['rate<0.1'],    // Error rate must be below 10%
  },
};

const BASE_URL = 'http://localhost:3000';

export default function () {
  // User registration
  const registerPayload = JSON.stringify({
    name: `User ${Math.random()}`,
    email: `user${Math.random()}@example.com`,
    password: 'Password123!'
  });

  const registerRes = http.post(`${BASE_URL}/api/users`, registerPayload, {
    headers: { 'Content-Type': 'application/json' },
  });

  check(registerRes, {
    'registration successful': (r) => r.status === 201,
    'registration time < 500ms': (r) => r.timings.duration < 500,
  });

  sleep(1);

  // User login
  const loginPayload = JSON.stringify({
    email: 'test@example.com',
    password: 'Password123!'
  });

  const loginRes = http.post(`${BASE_URL}/api/auth/login`, loginPayload, {
    headers: { 'Content-Type': 'application/json' },
  });

  check(loginRes, {
    'login successful': (r) => r.status === 200,
    'login time < 300ms': (r) => r.timings.duration < 300,
  });

  const token = loginRes.json('token');

  sleep(1);

  // Get user profile
  const profileRes = http.get(`${BASE_URL}/api/users/me`, {
    headers: { 'Authorization': `Bearer ${token}` },
  });

  check(profileRes, {
    'profile fetch successful': (r) => r.status === 200,
    'profile fetch time < 200ms': (r) => r.timings.duration < 200,
  });

  sleep(1);

  // Create post
  const postPayload = JSON.stringify({
    title: `Post ${Math.random()}`,
    content: `Content ${Math.random()}`
  });

  const postRes = http.post(`${BASE_URL}/api/posts`, postPayload, {
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
  });

  check(postRes, {
    'post creation successful': (r) => r.status === 201,
    'post creation time < 400ms': (r) => r.timings.duration < 400,
  });

  sleep(1);
}
```

## Security Testing

### 1. Security Test Examples

```javascript
// Security Tests
import request from 'supertest';
import app from '../src/app';

describe('Security Tests', () => {
  describe('SQL Injection Prevention', () => {
    it('should prevent SQL injection in user search', async () => {
      // Arrange
      const maliciousInput = "'; DROP TABLE users; --";

      // Act & Assert
      await request(app)
        .get(`/api/users/search?q=${encodeURIComponent(maliciousInput)}`)
        .expect(400);
    });

    it('should prevent SQL injection in login', async () => {
      // Arrange
      const maliciousInput = "' OR '1'='1";

      // Act & Assert
      await request(app)
        .post('/api/auth/login')
        .send({
          email: maliciousInput,
          password: 'password'
        })
        .expect(400);
    });
  });

  describe('XSS Prevention', () => {
    it('should prevent XSS in user input', async () => {
      // Arrange
      const maliciousInput = '<script>alert("XSS")</script>';

      // Act
      const response = await request(app)
        .post('/api/users')
        .send({
          name: maliciousInput,
          email: 'test@example.com',
          password: 'password123'
        })
        .expect(201);

      // Assert
      expect(response.body.name).not.toContain('<script>');
      expect(response.body.name).toContain('&lt;script&gt;');
    });
  });

  describe('CSRF Protection', () => {
    it('should require CSRF token for state-changing operations', async () => {
      // Act & Assert
      await request(app)
        .post('/api/users')
        .send({
          name: 'Test User',
          email: 'test@example.com',
          password: 'password123'
        })
        .expect(403); // Should fail without CSRF token
    });
  });

  describe('Authentication Bypass', () => {
    it('should not allow access to protected routes without token', async () => {
      // Act & Assert
      await request(app)
        .get('/api/users/me')
        .expect(401);
    });

    it('should not allow access with invalid token', async () => {
      // Act & Assert
      await request(app)
        .get('/api/users/me')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);
    });
  });

  describe('Rate Limiting', () => {
    it('should limit login attempts', async () => {
      // Act
      for (let i = 0; i < 6; i++) {
        await request(app)
          .post('/api/auth/login')
          .send({
            email: 'test@example.com',
            password: 'wrongpassword'
          });
      }

      // Assert
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'wrongpassword'
        })
        .expect(429); // Too Many Requests
    });
  });
});
```

## Test Automation

### 1. CI/CD Test Pipeline

```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run unit tests
      run: npm run test:unit
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/lcov.info

  integration-tests:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run integration tests
      run: npm run test:integration
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/test_db
        REDIS_URL: redis://localhost:6379

  e2e-tests:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Start application
      run: npm run start:test &
      env:
        NODE_ENV: test
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/test_db
        REDIS_URL: redis://localhost:6379
    
    - name: Wait for application
      run: npx wait-on http://localhost:3000
    
    - name: Run E2E tests
      run: npm run test:e2e
    
    - name: Upload screenshots
      uses: actions/upload-artifact@v3
      if: failure()
      with:
        name: cypress-screenshots
        path: cypress/screenshots

  performance-tests:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Start application
      run: npm run start:test &
      env:
        NODE_ENV: test
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/test_db
        REDIS_URL: redis://localhost:6379
    
    - name: Wait for application
      run: npx wait-on http://localhost:3000
    
    - name: Run performance tests
      run: npm run test:performance
    
    - name: Upload performance report
      uses: actions/upload-artifact@v3
      with:
        name: performance-report
        path: performance-report.json
```

This testing guide provides comprehensive coverage of modern testing practices, including unit testing, integration testing, end-to-end testing, performance testing, security testing, and test automation. Each section includes practical examples and best practices for building reliable and maintainable test suites.
