# Frontend Development Guide

## Table of Contents
1. [Modern Frontend Frameworks](#modern-frontend-frameworks)
2. [State Management](#state-management)
3. [Performance Optimization](#performance-optimization)
4. [User Experience Design](#user-experience-design)
5. [Component Architecture](#component-architecture)
6. [Styling & CSS](#styling--css)
7. [Testing Strategies](#testing-strategies)
8. [Build & Deployment](#build--deployment)

## Modern Frontend Frameworks

### 1. React.js
**Key Features:**
- Virtual DOM for efficient rendering
- Component-based architecture
- Large ecosystem and community
- JSX syntax

**Best Practices:**
```jsx
// Functional Component with Hooks
import React, { useState, useEffect } from 'react';

const UserProfile = ({ userId }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const response = await fetch(`/api/users/${userId}`);
        const userData = await response.json();
        setUser(userData);
      } catch (error) {
        console.error('Error fetching user:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, [userId]);

  if (loading) return <div>Loading...</div>;
  if (!user) return <div>User not found</div>;

  return (
    <div className="user-profile">
      <h2>{user.name}</h2>
      <p>{user.email}</p>
    </div>
  );
};

export default UserProfile;
```

### 2. Vue.js
**Key Features:**
- Progressive framework
- Template-based syntax
- Built-in state management (Vuex)
- Excellent documentation

**Best Practices:**
```vue
<template>
  <div class="user-profile">
    <h2>{{ user.name }}</h2>
    <p>{{ user.email }}</p>
    <button @click="updateProfile">Update Profile</button>
  </div>
</template>

<script>
export default {
  name: 'UserProfile',
  data() {
    return {
      user: null,
      loading: true
    };
  },
  async mounted() {
    await this.fetchUser();
  },
  methods: {
    async fetchUser() {
      try {
        const response = await fetch(`/api/users/${this.userId}`);
        this.user = await response.json();
      } catch (error) {
        console.error('Error fetching user:', error);
      } finally {
        this.loading = false;
      }
    },
    updateProfile() {
      // Profile update logic
    }
  }
};
</script>
```

### 3. Angular
**Key Features:**
- Full-featured framework
- TypeScript support
- Dependency injection
- Built-in testing utilities

**Best Practices:**
```typescript
import { Component, OnInit } from '@angular/core';
import { UserService } from '../services/user.service';

@Component({
  selector: 'app-user-profile',
  template: `
    <div class="user-profile">
      <h2>{{ user?.name }}</h2>
      <p>{{ user?.email }}</p>
    </div>
  `
})
export class UserProfileComponent implements OnInit {
  user: any = null;
  loading = true;

  constructor(private userService: UserService) {}

  async ngOnInit() {
    try {
      this.user = await this.userService.getUser(this.userId);
    } catch (error) {
      console.error('Error fetching user:', error);
    } finally {
      this.loading = false;
    }
  }
}
```

## State Management

### 1. Redux (React)
**Core Concepts:**
- Single source of truth
- State is read-only
- Changes through pure functions

**Implementation:**
```javascript
// Action Types
const FETCH_USER_REQUEST = 'FETCH_USER_REQUEST';
const FETCH_USER_SUCCESS = 'FETCH_USER_SUCCESS';
const FETCH_USER_FAILURE = 'FETCH_USER_FAILURE';

// Action Creators
const fetchUserRequest = () => ({ type: FETCH_USER_REQUEST });
const fetchUserSuccess = (user) => ({ type: FETCH_USER_SUCCESS, payload: user });
const fetchUserFailure = (error) => ({ type: FETCH_USER_FAILURE, payload: error });

// Reducer
const userReducer = (state = { user: null, loading: false, error: null }, action) => {
  switch (action.type) {
    case FETCH_USER_REQUEST:
      return { ...state, loading: true, error: null };
    case FETCH_USER_SUCCESS:
      return { ...state, user: action.payload, loading: false };
    case FETCH_USER_FAILURE:
      return { ...state, error: action.payload, loading: false };
    default:
      return state;
  }
};

// Async Action
const fetchUser = (userId) => async (dispatch) => {
  dispatch(fetchUserRequest());
  try {
    const response = await fetch(`/api/users/${userId}`);
    const user = await response.json();
    dispatch(fetchUserSuccess(user));
  } catch (error) {
    dispatch(fetchUserFailure(error.message));
  }
};
```

### 2. Vuex (Vue.js)
**Store Structure:**
```javascript
import { createStore } from 'vuex';

export default createStore({
  state: {
    user: null,
    loading: false,
    error: null
  },
  mutations: {
    SET_USER(state, user) {
      state.user = user;
    },
    SET_LOADING(state, loading) {
      state.loading = loading;
    },
    SET_ERROR(state, error) {
      state.error = error;
    }
  },
  actions: {
    async fetchUser({ commit }, userId) {
      commit('SET_LOADING', true);
      commit('SET_ERROR', null);
      
      try {
        const response = await fetch(`/api/users/${userId}`);
        const user = await response.json();
        commit('SET_USER', user);
      } catch (error) {
        commit('SET_ERROR', error.message);
      } finally {
        commit('SET_LOADING', false);
      }
    }
  },
  getters: {
    isAuthenticated: state => !!state.user,
    userFullName: state => state.user ? `${state.user.firstName} ${state.user.lastName}` : ''
  }
});
```

### 3. NgRx (Angular)
**Store Implementation:**
```typescript
// Actions
export const fetchUser = createAction('[User] Fetch User', props<{ userId: string }>());
export const fetchUserSuccess = createAction('[User] Fetch User Success', props<{ user: User }>());
export const fetchUserFailure = createAction('[User] Fetch User Failure', props<{ error: string }>());

// Effects
@Injectable()
export class UserEffects {
  fetchUser$ = createEffect(() =>
    this.actions$.pipe(
      ofType(fetchUser),
      mergeMap(({ userId }) =>
        this.userService.getUser(userId).pipe(
          map(user => fetchUserSuccess({ user })),
          catchError(error => of(fetchUserFailure({ error: error.message })))
        )
      )
    )
  );

  constructor(
    private actions$: Actions,
    private userService: UserService
  ) {}
}

// Reducer
export const userReducer = createReducer(
  initialState,
  on(fetchUser, state => ({ ...state, loading: true })),
  on(fetchUserSuccess, (state, { user }) => ({ ...state, user, loading: false })),
  on(fetchUserFailure, (state, { error }) => ({ ...state, error, loading: false }))
);
```

## Performance Optimization

### 1. Code Splitting
```javascript
// React - Lazy Loading
import React, { lazy, Suspense } from 'react';

const UserProfile = lazy(() => import('./UserProfile'));

function App() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <UserProfile />
    </Suspense>
  );
}

// Vue.js - Dynamic Imports
const UserProfile = () => import('./UserProfile.vue');

// Angular - Lazy Loading
const routes: Routes = [
  {
    path: 'user',
    loadChildren: () => import('./user/user.module').then(m => m.UserModule)
  }
];
```

### 2. Memoization
```javascript
// React - useMemo and useCallback
import React, { useMemo, useCallback } from 'react';

const UserList = ({ users, filter }) => {
  const filteredUsers = useMemo(() => {
    return users.filter(user => user.name.includes(filter));
  }, [users, filter]);

  const handleUserClick = useCallback((userId) => {
    console.log('User clicked:', userId);
  }, []);

  return (
    <div>
      {filteredUsers.map(user => (
        <UserItem key={user.id} user={user} onClick={handleUserClick} />
      ))}
    </div>
  );
};
```

### 3. Virtual Scrolling
```javascript
// React Virtualized
import { FixedSizeList as List } from 'react-window';

const UserList = ({ users }) => {
  const Row = ({ index, style }) => (
    <div style={style}>
      <UserItem user={users[index]} />
    </div>
  );

  return (
    <List
      height={400}
      itemCount={users.length}
      itemSize={50}
      width="100%"
    >
      {Row}
    </List>
  );
};
```

## User Experience Design

### 1. Responsive Design
```css
/* Mobile First Approach */
.container {
  width: 100%;
  padding: 1rem;
}

/* Tablet */
@media (min-width: 768px) {
  .container {
    max-width: 750px;
    margin: 0 auto;
  }
}

/* Desktop */
@media (min-width: 1024px) {
  .container {
    max-width: 1000px;
  }
}
```

### 2. Accessibility (a11y)
```jsx
// React Accessibility Example
const AccessibleButton = ({ onClick, children, ariaLabel }) => (
  <button
    onClick={onClick}
    aria-label={ariaLabel}
    role="button"
    tabIndex={0}
    onKeyPress={(e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        onClick();
      }
    }}
  >
    {children}
  </button>
);
```

### 3. Loading States
```jsx
// Skeleton Loading Component
const SkeletonLoader = () => (
  <div className="skeleton">
    <div className="skeleton-avatar"></div>
    <div className="skeleton-content">
      <div className="skeleton-title"></div>
      <div className="skeleton-text"></div>
      <div className="skeleton-text"></div>
    </div>
  </div>
);

// CSS for Skeleton
.skeleton {
  display: flex;
  gap: 1rem;
  padding: 1rem;
}

.skeleton-avatar {
  width: 50px;
  height: 50px;
  background: linear-gradient(90deg, #f0f0f0 25%, #e0e0e0 50%, #f0f0f0 75%);
  background-size: 200% 100%;
  animation: loading 1.5s infinite;
  border-radius: 50%;
}

.skeleton-content {
  flex: 1;
}

.skeleton-title {
  height: 20px;
  background: linear-gradient(90deg, #f0f0f0 25%, #e0e0e0 50%, #f0f0f0 75%);
  background-size: 200% 100%;
  animation: loading 1.5s infinite;
  margin-bottom: 0.5rem;
}

@keyframes loading {
  0% { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}
```

## Component Architecture

### 1. Component Patterns
```jsx
// Compound Component Pattern
const Tabs = ({ children }) => {
  const [activeTab, setActiveTab] = useState(0);
  
  return (
    <TabsContext.Provider value={{ activeTab, setActiveTab }}>
      {children}
    </TabsContext.Provider>
  );
};

Tabs.TabList = ({ children }) => (
  <div className="tab-list">
    {children}
  </div>
);

Tabs.Tab = ({ index, children }) => {
  const { activeTab, setActiveTab } = useContext(TabsContext);
  
  return (
    <button
      className={`tab ${activeTab === index ? 'active' : ''}`}
      onClick={() => setActiveTab(index)}
    >
      {children}
    </button>
  );
};

Tabs.TabPanel = ({ index, children }) => {
  const { activeTab } = useContext(TabsContext);
  
  return activeTab === index ? <div className="tab-panel">{children}</div> : null;
};
```

### 2. Higher-Order Components (HOC)
```jsx
// Authentication HOC
const withAuth = (WrappedComponent) => {
  return function AuthenticatedComponent(props) {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
      // Check authentication status
      checkAuth().then(setIsAuthenticated).finally(() => setLoading(false));
    }, []);

    if (loading) return <div>Loading...</div>;
    if (!isAuthenticated) return <LoginPage />;

    return <WrappedComponent {...props} />;
  };
};

// Usage
const ProtectedUserProfile = withAuth(UserProfile);
```

## Styling & CSS

### 1. CSS-in-JS
```javascript
// Styled Components
import styled from 'styled-components';

const Button = styled.button`
  background: ${props => props.primary ? '#007bff' : '#6c757d'};
  color: white;
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  
  &:hover {
    opacity: 0.8;
  }
  
  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
`;

// Usage
<Button primary>Primary Button</Button>
<Button>Secondary Button</Button>
```

### 2. CSS Modules
```css
/* UserProfile.module.css */
.container {
  padding: 1rem;
  border: 1px solid #ddd;
  border-radius: 8px;
}

.title {
  color: #333;
  font-size: 1.5rem;
  margin-bottom: 1rem;
}

.avatar {
  width: 100px;
  height: 100px;
  border-radius: 50%;
  object-fit: cover;
}
```

```jsx
// Usage in React
import styles from './UserProfile.module.css';

const UserProfile = ({ user }) => (
  <div className={styles.container}>
    <h2 className={styles.title}>{user.name}</h2>
    <img src={user.avatar} alt={user.name} className={styles.avatar} />
  </div>
);
```

## Testing Strategies

### 1. Unit Testing
```javascript
// Jest + React Testing Library
import { render, screen, fireEvent } from '@testing-library/react';
import UserProfile from './UserProfile';

describe('UserProfile', () => {
  test('renders user information', () => {
    const user = { name: 'John Doe', email: 'john@example.com' };
    render(<UserProfile user={user} />);
    
    expect(screen.getByText('John Doe')).toBeInTheDocument();
    expect(screen.getByText('john@example.com')).toBeInTheDocument();
  });

  test('handles update button click', () => {
    const mockOnUpdate = jest.fn();
    const user = { name: 'John Doe', email: 'john@example.com' };
    
    render(<UserProfile user={user} onUpdate={mockOnUpdate} />);
    
    fireEvent.click(screen.getByText('Update Profile'));
    expect(mockOnUpdate).toHaveBeenCalledWith(user);
  });
});
```

### 2. Integration Testing
```javascript
// Testing API integration
import { render, screen, waitFor } from '@testing-library/react';
import { rest } from 'msw';
import { setupServer } from 'msw/node';
import UserProfile from './UserProfile';

const server = setupServer(
  rest.get('/api/users/:id', (req, res, ctx) => {
    return res(
      ctx.json({
        id: req.params.id,
        name: 'John Doe',
        email: 'john@example.com'
      })
    );
  })
);

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

test('fetches and displays user data', async () => {
  render(<UserProfile userId="123" />);
  
  await waitFor(() => {
    expect(screen.getByText('John Doe')).toBeInTheDocument();
  });
});
```

## Build & Deployment

### 1. Webpack Configuration
```javascript
// webpack.config.js
const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');

module.exports = {
  entry: './src/index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].[contenthash].js',
    clean: true
  },
  module: {
    rules: [
      {
        test: /\.(js|jsx)$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader'
        }
      },
      {
        test: /\.css$/,
        use: [MiniCssExtractPlugin.loader, 'css-loader']
      }
    ]
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: './public/index.html'
    }),
    new MiniCssExtractPlugin({
      filename: '[name].[contenthash].css'
    })
  ],
  optimization: {
    splitChunks: {
      chunks: 'all'
    }
  }
};
```

### 2. Environment Configuration
```javascript
// .env files
REACT_APP_API_URL=https://api.example.com
REACT_APP_ENVIRONMENT=production
REACT_APP_ANALYTICS_ID=GA-123456789

// Environment-specific config
const config = {
  apiUrl: process.env.REACT_APP_API_URL,
  environment: process.env.REACT_APP_ENVIRONMENT,
  analyticsId: process.env.REACT_APP_ANALYTICS_ID
};
```

## Best Practices Checklist

- [ ] Use semantic HTML elements
- [ ] Implement responsive design
- [ ] Optimize for performance
- [ ] Ensure accessibility compliance
- [ ] Write comprehensive tests
- [ ] Use TypeScript for type safety
- [ ] Implement error boundaries
- [ ] Add loading states
- [ ] Optimize bundle size
- [ ] Use modern CSS features
- [ ] Implement proper SEO
- [ ] Add analytics tracking
- [ ] Ensure cross-browser compatibility
- [ ] Implement proper error handling
- [ ] Use consistent coding standards
