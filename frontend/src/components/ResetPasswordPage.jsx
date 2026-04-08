import { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import axios from 'axios';

export default function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const token = searchParams.get('token');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!token) {
      setError('Invalid or missing reset token. Please request a new reset link.');
    }
  }, [token]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (newPassword.length < 6) {
      setError('Password must be at least 6 characters');
      return;
    }
    setLoading(true);
    try {
      const response = await axios.post('http://localhost:8081/api/auth/reset-password', {
        token,
        newPassword,
        confirmPassword
      });
      setMessage(response.data.message || 'Password reset successful! Redirecting to login...');
      setTimeout(() => navigate('/login'), 2000);
    } catch (err) {
      setError(err.response?.data?.message || 'Reset failed. Token may be invalid/expired. Request new link.');
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="loading">Processing...</div>;

  return (
    <div className="reset-password-page glass-effect">
      <div className="form-container">
        <h2>Reset Your Password</h2>
        {error && <div className="error-message">{error}</div>}
        {message && <div className="success-message">{message}</div>}
        {token ? (
          <form onSubmit={handleSubmit} className="reset-form">
            <div className="form-group">
              <label>New Password</label>
              <input
                type="password"
                placeholder="Enter new password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="form-input"
                required
              />
            </div>
            <div className="form-group">
              <label>Confirm Password</label>
              <input
                type="password"
                placeholder="Confirm new password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="form-input"
                required
              />
            </div>
            <button type="submit" className="primary-btn" disabled={loading}>
              Reset Password
            </button>
          </form>
        ) : (
          <p>Redirecting...</p>
        )}
        <p className="back-link">
          <button onClick={() => navigate('/login')} className="text-btn">
            Back to Login
          </button>
        </p>
      </div>
    </div>
  );
}
