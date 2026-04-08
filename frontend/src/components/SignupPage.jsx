import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from 'axios';
import { ShieldCheck, User, Mail, Lock, Eye, EyeOff, ArrowRight, Check, CheckCircle } from "lucide-react";


export default function SignupPage() {
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: ""
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const [serverError, setServerError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    // Clear error on change
    if (errors[e.target.name]) {
      setErrors({ ...errors, [e.target.name]: "" });
    }
  };

  const validateForm = () => {
    const newErrors = {};

    if (!formData.name.trim()) {
      newErrors.name = "Name is required";
    } else if (formData.name.length < 2) {
      newErrors.name = "Name must be at least 2 characters";
    }

    if (!formData.email) {
      newErrors.email = "Email is required";
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = "Email is invalid";
    }

    if (!formData.password) {
      newErrors.password = "Password is required";
    } else if (formData.password.length < 6) {
      newErrors.password = "Password must be at least 6 characters";
    }

    if (formData.confirmPassword !== formData.password) {
      newErrors.confirmPassword = "Passwords do not match";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validateForm()) return;

    setIsLoading(true);
    try {
      const response = await axios.post('http://localhost:8081/api/auth/register', {
        name: formData.name,
        email: formData.email,
        password: formData.password
      });
      
      setSuccessMessage(response.data.message || 'Account created successfully!');
      setTimeout(() => navigate('/login'), 1500);
    } catch (error) {
      setServerError(error.response?.data?.message || 'Signup failed. Please try again.');
      setErrors({});
    }
    setIsLoading(false);
    setServerError("");
    setSuccessMessage("");
  };


  return (
    <div className="login-page">
      <div className="login-container">
        <div className="login-header">
          <div className="login-logo">
            <ShieldCheck className="logo-icon" />
            <span>PhishGuard</span>
          </div>
          <h1 className="login-title">Create Account</h1>
          <p className="login-subtitle">
            Join thousands of users protected from phishing attacks
          </p>
        </div>

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Full Name</label>
            <div className="input-wrapper">
              <User className="input-icon" />
              <input
                type="text"
                name="name"
                className={`form-input ${errors.name ? 'input-error' : ''}`}
                placeholder="Enter your full name"
                value={formData.name}
                onChange={handleChange}
              />
            </div>
            {errors.name && <div className="error-message">{errors.name}</div>}
          </div>

          <div className="form-group">
            <label className="form-label">Email Address</label>
            <div className="input-wrapper">
              <Mail className="input-icon" />
              <input
                type="email"
                name="email"
                className={`form-input ${errors.email ? 'input-error' : ''}`}
                placeholder="Enter your email"
                value={formData.email}
                onChange={handleChange}
              />
            </div>
            {errors.email && <div className="error-message">{errors.email}</div>}
          </div>

          <div className="form-group">
            <label className="form-label">Password</label>
            <div className="input-wrapper">
              <Lock className="input-icon" />
              <input
                type={showPassword ? "text" : "password"}
                name="password"
                className={`form-input ${errors.password ? 'input-error' : ''}`}
                placeholder="Create a password"
                value={formData.password}
                onChange={handleChange}
              />

              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? <EyeOff /> : <Eye />}
              </button>
            </div>
            {errors.password && <div className="error-message">{errors.password}</div>}
            <small style={{ color: '#6b7280', fontSize: '0.8rem' }}>
              Must be at least 6 characters long
            </small>
          </div>

          <div className="form-group">
            <label className="form-label">Confirm Password</label>
            <div className="input-wrapper">
              <Lock className="input-icon" />
              <input
                type={showConfirmPassword ? "text" : "password"}
                name="confirmPassword"
                className={`form-input ${errors.confirmPassword ? 'input-error' : ''}`}
                placeholder="Confirm your password"
                value={formData.confirmPassword}
                onChange={handleChange}
              />

              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              >
                {showConfirmPassword ? <EyeOff /> : <Eye />}
              </button>
            </div>
            {errors.confirmPassword && <div className="error-message">{errors.confirmPassword}</div>}
          </div>

          {serverError && (
            <div className="error-message" style={{ marginBottom: '1rem', textAlign: 'center', padding: '0.75rem', background: '#fee2e2', border: '1px solid #fecaca', borderRadius: '0.5rem' }}>
              {serverError}
            </div>
          )}
          {successMessage && (
            <div className="success-message" style={{ marginBottom: '1rem', textAlign: 'center', padding: '0.75rem', background: '#d1fae5', border: '1px solid #a7f3d0', borderRadius: '0.5rem', color: '#065f46' }}>
              {successMessage}
            </div>
          )}
          <button className="submit-button" disabled={isLoading}>
            {isLoading ? (
              <div className="loading-spinner">
                <div style={{ width: '20px', height: '20px', border: '2px solid #ffffff40', borderTop: '2px solid white', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
                Creating Account...
              </div>
            ) : (
              <>
                <ArrowRight className="submit-icon" />
                Create Account
              </>
            )}
          </button>
        </form>

        <div className="login-footer">
          <p>
            Already have an account?{" "}
            <Link to="/login" className="toggle-form-btn">
              Sign in here
            </Link>
          </p>
        </div>

        <div className="login-benefits">
          <h3><CheckCircle className="inline-icon" size={18} /> What you'll get</h3>
          <ul>
            <li>✅ Unlimited URL scans per day</li>
            <li>✅ Personalized scan history</li>
            <li>✅ Real-time phishing alerts</li>
            <li>✅ Priority threat intelligence</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

