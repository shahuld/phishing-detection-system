import { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import axios from 'axios';

const Dashboard = () => {
  const { token } = useAuth();
  const [history, setHistory] = useState([]);
  const [userProfile, setUserProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [historyRes, profileRes] = await Promise.all([
        axios.get('http://localhost:8081/api/history', {
          headers: { Authorization: `Bearer ${token}` }
        }),
        axios.get('http://localhost:8081/api/auth/profile', {
          headers: { Authorization: `Bearer ${token}` }
        })
      ]);
      setHistory(historyRes.data);
      setUserProfile(profileRes.data);
    } catch (error) {
      console.error('Failed to fetch data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div>Loading dashboard...</div>;

  return (
    <div className="dashboard-page">
      <div className="dashboard-container">
        <div className="dashboard-header">
          <h1>Welcome, {userProfile?.name || 'User'}!</h1>
          <p>Your account details and scan history</p>
        </div>
        
        <div className="user-details-card">
          <h3>Account Info</h3>
          <p><strong>Name:</strong> {userProfile?.name || 'N/A'}</p>
          <p><strong>Email:</strong> {userProfile?.email || 'N/A'}</p>
        </div>

        <div className="history-card">
          <table className="history-table">
            <thead>
              <tr>
                <th>URL</th>
                <th>Phishing Score</th>
                <th>Status</th>
                <th>Scanned</th>
              </tr>
            </thead>
            <tbody>
              {history.map((item) => (
                <tr key={item.id}>
                  <td>
                    <a href={item.url} target="_blank" rel="noopener noreferrer">
                      {item.url}
                    </a>
                  </td>
                  <td className="score">{item.phishingScore?.toFixed(1)}%</td>
                  <td>
                    <span className={`badge ${item.isPhishing ? 'phishing' : 'safe'}`}>
                      {item.isPhishing ? '⚠️ Phishing' : '✅ Safe'}
                    </span>
                  </td>
                  <td>{new Date(item.scannedAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {history.length === 0 && (
          <div className="empty-state-card">
            <p>No scan history available.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
