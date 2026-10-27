import { request, setAuthToken } from './apiClient';

export interface User {
  id: string;
  email: string;
  full_name: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user_id: string;
  email: string;
  full_name: string;
}

export const authService = {
  login: async (email: string, password: string): Promise<AuthResponse> => {
    const data = await request<AuthResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: email.trim().toLowerCase(), password }),
    });
    setAuthToken(data.access_token);
    return data;
  },

  register: async (payload: {
    full_name: string;
    email: string;
    password: string;
    confirm_password: string;
  }): Promise<AuthResponse> => {
    const data = await request<AuthResponse>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        full_name: payload.full_name.trim(),
        email: payload.email.trim().toLowerCase(),
        password: payload.password,
        confirm_password: payload.confirm_password,
      }),
    });
    setAuthToken(data.access_token);
    return data;
  },

  getCurrentUser: async (): Promise<User> => {
    return request<User>('/auth/me');
  },

  logout: async (): Promise<void> => {
    try {
      await request('/auth/logout', { method: 'POST' });
    } catch {
      // Ignore network errors during logout
    } finally {
      setAuthToken(null);
    }
  },
};
