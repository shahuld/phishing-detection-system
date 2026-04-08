import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from 'axios';
import { ShieldCheck, Mail, Lock, Eye, EyeOff, ArrowRight, Check } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";


export default function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState(""); 
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [showForgotModal, setShowForgotModal] = useState(false);
  const [forgotEmail, setForgotEmail] = useState("");
  const [forgotSuccess, setForgotSuccess] = useState(false);
  const [errors, setErrors] = useState({});
  const [emailError, setEmailError] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [serverError, setServerError] = useState(""); 
  const navigate = useNavigate();

  // Animate on mount
  const [isVisible, setIsVisible] = useState(false);
  useEffect(() => {
    setIsVisible(true);
  }, []);

  const validateForm = () => {
    const newErrors = {};
    if (!email) {
      newErrors.email = "Email is required";
    } else if (!/\S+@\S+\.\S+/.test(email)) {
      newErrors.email = "Email is invalid";
    }
    if (!password) {
      newErrors.password = "Password is required";
    } else if (password.length < 6) {
      newErrors.password = "Password must be at least 6 characters";
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validateForm()) return;

    setIsLoading(true);
    try {
      console.log('Login payload:', { email, password });
      const response = await axios.post('http://localhost:8081/api/auth/login', {
        email,
        password
      });
      
      if (response.data.token) {
        login(response.data.token);
        setTimeout(() => navigate('/'), 1000);
      }
    } catch (error) {
      console.error('Full login error:', error.response);
      setServerError(error.response?.data?.message || 'Login failed. Please check your credentials.');
      setEmailError("");
      setPasswordError(""); 
    }
    setIsLoading(false);
    if (!serverError) {
      setServerError("");
    }
  };

  const handleForgotPassword = async () => {
    if (!forgotEmail.trim()) {
      alert('Enter email');
      return;
    }
    setIsLoading(true);
    try {
      await axios.post('http://localhost:8081/api/auth/forgot-password', { email: forgotEmail });
      setForgotSuccess(true);
      setTimeout(() => {
        setShowForgotModal(false);
        setForgotSuccess(false);
        setForgotEmail('');
      }, 3000);
    } catch (error) {
      console.error('Forgot password request failed:', error.response?.data || error);
      // Generic message for security - don't reveal if email exists
      alert('If your email is registered with PhishGuard, check your inbox for reset instructions shortly.');
    }
    setIsLoading(false);
  };



  return (
    <div className="login-page">
      <div className="login-container">
        <div className="login-header">
          <div className="login-logo">
            <ShieldCheck className="logo-icon" />
            <span>PhishGuard</span>
          </div>
          <h1 className="login-title">Welcome Back</h1>
          <p className="login-subtitle">
            Sign in to your account to access advanced phishing protection
          </p>
        </div>

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Email Address</label>
            <div className="input-wrapper">
              <Mail className="input-icon" />
              <input
                type="email"
                className={`form-input ${emailError ? 'input-error' : ''}`}
                placeholder="Enter your email"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  setEmailError("");
                }}
                onBlur={() => {
                  if (!email) setEmailError("Email is required");
                  else if (!/\S+@\S+\.\S+/.test(email)) setEmailError("Invalid email");
                  else setEmailError("");
                }}
              />
            </div>
            {emailError && <div className="error-message">{emailError}</div>}
          </div>

          <div className="form-group">
            <label className="form-label">Password</label>
            <div className="input-wrapper">
              <Lock className="input-icon" />
              <input
                type={showPassword ? "text" : "password"}
                className={`form-input ${passwordError ? 'input-error' : ''}`}
                placeholder="Enter your password"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setPasswordError("");
                }}
                onBlur={() => {
                  if (!password) setPasswordError("Password is required");
                  else if (password.length < 6) setPasswordError("Password must be at least 6 characters");
                  else setPasswordError("");
                }}
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? <EyeOff /> : <Eye />}
              </button>
            </div>
            {passwordError && <div className="error-message">{passwordError}</div>}
          </div>

          {serverError && (
            <div className="error-message" style={{ marginBottom: '1rem', textAlign: 'center', padding: '0.75rem', background: '#fee2e2', border: '1px solid #fecaca', borderRadius: '0.5rem' }}>
              {serverError}
            </div>
          )}
          <div className="form-options">
            <label className="remember-me">
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
              />
              Remember me
            </label>
            <button type="button" className="forgot-password-link" onClick={() => setShowForgotModal(true)}>
              Forgot Password?
            </button>
          </div>
{showForgotModal && (
            <div className="modal-overlay">
              <div className="modal glass-effect">
                <div className="modal-header">
                  <ShieldCheck className="modal-icon" />
                  <h3>Forgot Password?</h3>
                  <p>Enter your email to receive secure reset instructions</p>
                </div>
                <input
                  type="email"
                  placeholder="your.email@example.com"
                  value={forgotEmail}
                  onChange={(e) => setForgotEmail(e.target.value)}
                  className={`modal-input glass-effect ${forgotEmail ? 'has-value' : ''}`}
                />
                <div className="modal-buttons">
                  <button type="button" onClick={() => setShowForgotModal(false)} className="cancel-btn secondary">
                    Cancel
                  </button>
                  <button type="button" onClick={handleForgotPassword} className="reset-btn primary" disabled={!forgotEmail.trim() || isLoading}>
                    {isLoading ? (
                      <span className="loading">
                        <div className="spinner" />
                        Sending...
                      </span>
                    ) : 'Send Reset Link'}
                  </button>
                </div>
              </div>
            </div>
          )}
          {forgotSuccess && (
            <div className="success-message">
              Reset link sent! Check your email.
            </div>
          )}

          <button className="submit-button" disabled={isLoading}>
            {isLoading ? (
              <div className="loading-spinner">
                <div style={{ width: '20px', height: '20px', border: '2px solid #ffffff40', borderTop: '2px solid white', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
                Signing in...
              </div>
            ) : (
              <>
                <ArrowRight className="submit-icon" />
                Sign In
              </>
            )}
          </button>
        </form>

        <div className="login-footer">
          <p>
            Don't have an account?{" "}
            <Link to="/signup" className="toggle-form-btn">
              Sign up here
            </Link>
          </p>
        </div>

        <div className="login-benefits">
          <h3><Check className="inline-icon" size={18} /> Benefits of PhishGuard Account</h3>
          <ul>
            <li>Save scan history and results</li>
            <li>Custom alerts and notifications</li>
            <li>Priority support and features</li>
            <li>Advanced analytics dashboard</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

