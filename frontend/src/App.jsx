import { useState } from "react";
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { ShieldCheck, Menu, X, Home as HomeIcon, Globe, User, LogIn, LogOut } from "lucide-react";
import HomePage from "./components/HomePage";
import ServicesPage from "./components/ServicesPage";
import AboutPage from "./components/AboutPage";
import LoginPage from "./components/LoginPage";
import SignupPage from "./components/SignupPage";
import ResetPasswordPage from "./components/ResetPasswordPage";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import Dashboard from "./components/Dashboard";


import "./App.css";

const Navbar = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const location = useLocation();
  const { user, logout } = useAuth();

  const handleLogout = () => {
    logout();
  };

  return (
    <>
      <nav className="navbar">
        <div className="navbar-container">
          <div className="navbar-logo">
            <ShieldCheck className="logo-icon" />
            <span>PhishGuard</span>
          </div>

          <div className="navbar-menu">
            <Link to="/" className={`nav-link ${location.pathname === '/' ? 'active' : ''}`}>
              <HomeIcon className="nav-link-icon" />
              Home
            </Link>
            <Link to="/services" className={`nav-link ${location.pathname === '/services' ? 'active' : ''}`}>
              <Globe className="nav-link-icon" />
              Services
            </Link>
            <Link to="/about" className={`nav-link ${location.pathname === '/about' ? 'active' : ''}`}>
              <User className="nav-link-icon" />
              About
            </Link>
            {user ? (
              <>
                <Link to="/dashboard" className={`nav-link ${location.pathname === '/dashboard' ? 'active' : ''}`}>
                  <User className="nav-link-icon" />
                  Dashboard
                </Link>
                <button onClick={handleLogout} className="nav-link">
                  <LogOut className="nav-link-icon" />
                  Logout
                </button>
              </>
            ) : (
              <Link to="/login" className={`nav-link ${location.pathname === '/login' ? 'active' : ''}`}>
                <LogIn className="nav-link-icon" />
                Login
              </Link>
            )}

          </div>

          <button 
            className="mobile-menu-btn"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            {mobileMenuOpen ? <X /> : <Menu />}
          </button>
        </div>

        {mobileMenuOpen && (
          <div className="mobile-menu">
            <Link 
              to="/" 
              className={`mobile-nav-link ${location.pathname === '/' ? 'active' : ''}`}
              onClick={() => setMobileMenuOpen(false)}
            >
              <HomeIcon className="mobile-nav-icon" />
              Home
            </Link>
            <Link 
              to="/services" 
              className={`mobile-nav-link ${location.pathname === '/services' ? 'active' : ''}`}
              onClick={() => setMobileMenuOpen(false)}
            >
              <Globe className="mobile-nav-icon" />
              Services
            </Link>
            <Link 
              to="/about" 
              className={`mobile-nav-link ${location.pathname === '/about' ? 'active' : ''}`}
              onClick={() => setMobileMenuOpen(false)}
            >
              <User className="mobile-nav-icon" />
              About
            </Link>
            {user ? (
              <>
                <Link 
                  to="/dashboard" 
                  className={`mobile-nav-link ${location.pathname === '/dashboard' ? 'active' : ''}`}
                  onClick={() => setMobileMenuOpen(false)}
                >
                  <User className="mobile-nav-icon" />
                  Dashboard
                </Link>
                <button 
                  onClick={() => {
                    handleLogout();
                    setMobileMenuOpen(false);
                  }} 
                  className="mobile-nav-link"
                >
                  <LogOut className="mobile-nav-icon" />
                  Logout
                </button>
              </>
            ) : (
              <Link 
                to="/login" 
                className={`mobile-nav-link ${location.pathname === '/login' ? 'active' : ''}`}
                onClick={() => setMobileMenuOpen(false)}
              >
                <LogIn className="mobile-nav-icon" />
                Login
              </Link>
            )}

          </div>
        )}
      </nav>
    </>
  );
};

const AppContent = () => {
  return (
    <div className="app">
        <Navbar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/services" element={<ServicesPage />} />
            <Route path="/about" element={<AboutPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/signup" element={<SignupPage />} />
            <Route path="/reset-password" element={<ResetPasswordPage />} />
            <Route path="/dashboard" element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            } />
          </Routes>
        </main>
      </div>
  );
};

export default function App() {
  return (
    <Router future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </Router>
  );
}
