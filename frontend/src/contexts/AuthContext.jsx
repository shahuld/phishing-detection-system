import { createContext, useContext, useState, useEffect } from 'react';
import { jwtDecode } from 'jwt-decode';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        const decoded = jwtDecode(token);
        const id = decoded.id || decoded.sub || decoded.email;
        const email = decoded.email || decoded.sub;
        const name = decoded.name || 'User';
        setUser({ id, email, name });
        setToken(token);
      } catch (error) {
        console.error('Invalid JWT token:', error);
        localStorage.removeItem('token');
        setToken(null);
      }
    }
    setLoading(false);
  }, []);

  const login = (newToken) => {
    localStorage.setItem('token', newToken);
    try {
      const decoded = jwtDecode(newToken);
      const id = decoded.id || decoded.sub || decoded.email;
      const email = decoded.email || decoded.sub;
      const name = decoded.name || 'User';
      setUser({ id, email, name });
    } catch (error) {
      console.error('Invalid login token:', error);
    }
    setToken(newToken);
  };

  const logout = () => {
    localStorage.removeItem('token');
    setUser(null);
    setToken(null);
  };

  const value = {
    user,
    token,
    login,
    logout,
    loading
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
