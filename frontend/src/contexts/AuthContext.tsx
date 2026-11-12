import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { API_BASE_URL } from '@/config/api';

interface AuthContextType {
  token: string | null;
  isAuthenticated: boolean;
  isInitialized: boolean; // True when we've checked localStorage for existing token
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => Promise<void>;
  showLoginModal: boolean;
  setShowLoginModal: (show: boolean) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const TOKEN_STORAGE_KEY = 'gpm_cve_auth_token';

/**
 * Build API URL with fallback to relative addressing
 * @param endpoint - API endpoint path (e.g., '/api/v1/login/')
 * @returns Full URL if API_BASE_URL is set, otherwise relative URL
 */
const buildApiUrl = (endpoint: string): string => {
  const baseUrl = API_BASE_URL?.trim() || '';
  if (!baseUrl) {
    // Fallback to relative addressing
    return endpoint;
  }
  // Remove trailing slash from base URL and leading slash from endpoint if present
  const cleanBase = baseUrl.replace(/\/$/, '');
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return `${cleanBase}${cleanEndpoint}`;
};

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(null);
  const [isInitialized, setIsInitialized] = useState(false);
  const [showLoginModal, setShowLoginModal] = useState(false);

  // Load token from localStorage on mount
  useEffect(() => {
    const storedToken = localStorage.getItem(TOKEN_STORAGE_KEY);
    if (storedToken) {
      setToken(storedToken);
    }
    setIsInitialized(true);
  }, []);

  const login = async (username: string, password: string): Promise<boolean> => {
    try {
      const loginUrl = buildApiUrl('/api/v1/login/');
      const response = await fetch(loginUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Invalid username or password');
        }
        throw new Error(`Login failed: ${response.statusText}`);
      }

      const data = await response.json();
      const newToken = data.token;

      if (newToken) {
        setToken(newToken);
        localStorage.setItem(TOKEN_STORAGE_KEY, newToken);
        setShowLoginModal(false);
        return true;
      }

      throw new Error('No token received from server');
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  };

  const logout = async (): Promise<void> => {
    try {
      if (token) {
        // Call logout endpoint
        const logoutUrl = buildApiUrl('/api/v1/logout/');
        await fetch(logoutUrl, {
          method: 'POST',
          headers: {
            'Authorization': `Token ${token}`,
          },
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear token regardless of API call success
      setToken(null);
      localStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        token,
        isAuthenticated: !!token,
        isInitialized,
        login,
        logout,
        showLoginModal,
        setShowLoginModal,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

