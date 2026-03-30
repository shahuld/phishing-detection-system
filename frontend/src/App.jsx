import { useState } from "react";
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { ShieldCheck, Menu, X, Home as HomeIcon, Globe, User } from "lucide-react";
import HomePage from "./components/HomePage";
import ServicesPage from "./components/ServicesPage";
import AboutPage from "./components/AboutPage";

import "./App.css";

const Navbar = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const location = useLocation();

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
          </Routes>
        </main>
      </div>
  );
};

export default function App() {
  return (
    <Router>
      <AppContent />
    </Router>
  );
}
