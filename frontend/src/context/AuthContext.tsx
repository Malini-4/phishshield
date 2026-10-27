import React, { createContext, useContext, useEffect, useState } from 'react';
import { User, authService } from '../services/authService';
import { getAuthToken, setAuthToken } from '../services/apiClient';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (payload: {
    full_name: string;
    email: string;
    password: string;
    confirm_password: string;
  }) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const initAuth = async () => {
      const token = getAuthToken();
      if (!token) {
        setIsLoading(false);
        return;
      }
      try {
        const currentUser = await authService.getCurrentUser();
        setUser(currentUser);
      } catch {
        setAuthToken(null);
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    };

    initAuth();

    // Listen for unauthorized 401 events from apiClient
    const handleUnauthorized = () => {
      setAuthToken(null);
      setUser(null);
    };
    window.addEventListener('phishshield_unauthorized', handleUnauthorized);
    return () => {
      window.removeEventListener('phishshield_unauthorized', handleUnauthorized);
    };
  }, []);

  const login = async (email: string, password: string) => {
    const res = await authService.login(email, password);
    setUser({ id: res.user_id, email: res.email, full_name: res.full_name });
  };

  const register = async (payload: {
    full_name: string;
    email: string;
    password: string;
    confirm_password: string;
  }) => {
    const res = await authService.register(payload);
    setUser({ id: res.user_id, email: res.email, full_name: res.full_name });
  };

  const logout = async () => {
    try {
      await authService.logout();
    } finally {
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
