import { useState, useEffect, createContext, useContext } from 'react';
import axios from 'axios';
import toast from 'react-hot-toast';

interface User {
  id: string;
  email: string;
  roles: string[];
}

interface AuthContextType {
  user: User | null;
  login: (email: string, password: string, otp?: string) => Promise<void>;
  register: (email: string, password: string, invitationCode?: string) => Promise<void>;
  logout: () => void;
  logoutAll: () => void;
  setup2FA: () => Promise<{ secret: string; otpauth_uri: string }>;
  verify2FA: (code: string) => Promise<void>;
  requestPasswordReset: (email: string) => Promise<void>;
  confirmPasswordReset: (token: string, newPassword: string) => Promise<void>;
  requestEmailVerification: () => Promise<void>;
  confirmEmailVerification: (token: string) => Promise<void>;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8080',
  });

  // Add auth token to requests
  api.interceptors.request.use((config) => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  });

  const login = async (email: string, password: string, otp?: string) => {
    try {
      const response = await api.post('/auth/login', {
        email,
        password,
        otp,
      });
      
      const { token } = response.data;
      localStorage.setItem('auth_token', token);
      
      // Decode JWT to get user info (simplified)
      const payload = JSON.parse(atob(token.split('.')[1]));
      setUser({
        id: payload.sub,
        email,
        roles: payload.roles || [],
      });
      
      toast.success('Login successful!');
    } catch (error: any) {
      toast.error(error.response?.data || 'Login failed');
      throw error;
    }
  };

  const register = async (email: string, password: string, invitationCode?: string) => {
    try {
      await api.post('/auth/register', {
        email,
        password,
        invitation_code: invitationCode,
      });
      
      toast.success('Registration successful! Please verify your email.');
    } catch (error: any) {
      toast.error(error.response?.data || 'Registration failed');
      throw error;
    }
  };

  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('auth_token');
      setUser(null);
      toast.success('Logged out successfully');
    }
  };

  const logoutAll = async () => {
    try {
      await api.post('/auth/logout-all');
    } catch (error) {
      console.error('Logout all error:', error);
    } finally {
      localStorage.removeItem('auth_token');
      setUser(null);
      toast.success('All sessions logged out');
    }
  };

  const setup2FA = async () => {
    const response = await api.post('/auth/2fa/setup');
    return response.data;
  };

  const verify2FA = async (code: string) => {
    await api.post('/auth/2fa/verify', { code });
    toast.success('2FA enabled successfully!');
  };

  const requestPasswordReset = async (email: string) => {
    await api.post('/auth/password-reset/request', { email });
    toast.success('Password reset email sent!');
  };

  const confirmPasswordReset = async (token: string, newPassword: string) => {
    await api.post('/auth/password-reset/confirm', { token, new_password: newPassword });
    toast.success('Password reset successful!');
  };

  const requestEmailVerification = async () => {
    await api.post('/auth/email/verify/request');
    toast.success('Verification email sent!');
  };

  const confirmEmailVerification = async (token: string) => {
    await api.post('/auth/email/verify/confirm', { token });
    toast.success('Email verified successfully!');
  };

  useEffect(() => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        if (payload.exp * 1000 > Date.now()) {
          setUser({
            id: payload.sub,
            email: payload.email || '',
            roles: payload.roles || [],
          });
        } else {
          localStorage.removeItem('auth_token');
        }
      } catch (error) {
        localStorage.removeItem('auth_token');
      }
    }
    setLoading(false);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        login,
        register,
        logout,
        logoutAll,
        setup2FA,
        verify2FA,
        requestPasswordReset,
        confirmPasswordReset,
        requestEmailVerification,
        confirmEmailVerification,
        loading,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};