import { useState, useEffect } from "react";
import { ShieldCheck, Zap, Target, TrendingUp, Clock, Lock, Eye, AlertTriangle, CheckCircle, ArrowRight, X } from "lucide-react";

// Feature Detail Modal Component (local to HomePage)
function FeatureDetailModal({ feature, onClose }) {
  if (!feature) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose}>
          <X />
        </button>
        <div className="modal-icon">
          <feature.icon />
        </div>
        <h2 className="modal-title">{feature.title}</h2>
        <p className="modal-description">{feature.longDesc}</p>
        <ul className="modal-details">
          {feature.details.map((detail, i) => (
            <li key={i}>{detail}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

// Home Page Component
export default function HomePage({ setCurrentPage = () => {}, showToast = () => {} }) {

  const [selectedFeature, setSelectedFeature] = useState(null);

  const stats = [
    { icon: Zap, value: "0.3s", label: "Detection Speed" },
    { icon: Target, value: "99.7%", label: "Accuracy Rate" },
    { icon: TrendingUp, value: "2M+", label: "URLs Scanned" },
    { icon: ShieldCheck, value: "50K+", label: "Threats Blocked" }
  ];

  const features = [
    { 
      icon: Clock, 
      title: "Real-Time Analysis", 
      shortDesc: "Instant detection using advanced AI algorithms",
      longDesc: "Our AI-powered engine analyzes URLs in milliseconds, providing instant threat detection. The system processes millions of data points to identify phishing patterns, suspicious domains, and malicious redirects in real-time.",
      details: ["< 0.3s average response time", "Continuous monitoring", "Live threat feeds"]
    },
    { 
      icon: Target, 
      title: "High Precision", 
      shortDesc: "Minimal false positives with machine learning models",
      longDesc: "Our advanced machine learning models achieve 99.7% accuracy with industry-leading precision. The system continuously learns from global threat intelligence to minimize false positives while catching sophisticated phishing attempts.",
      details: ["99.7% detection accuracy", "Auto-learning algorithms", "Global threat database"]
    },
    { 
      icon: Lock, 
      title: "Secure Scanning", 
      shortDesc: "Safe analysis without exposing your data",
      longDesc: "Your privacy is our priority. Our secure scanning sandbox isolates suspicious URLs in a controlled environment, preventing any potential harm to your system. We never store or transmit your input data.",
      details: ["Sandbox isolation", "No data retention", "End-to-end encryption"]
    },
    { 
      icon: Eye, 
      title: "Deep Inspection", 
      shortDesc: "Multi-layer analysis of URL structures",
      longDesc: "Our deep inspection engine analyzes every aspect of a URL including domain age, SSL certificates, redirect chains, HTML content, and behavioral patterns. This multi-layer approach catches even the most sophisticated phishing attempts.",
      details: ["Domain age analysis", "SSL validation", "Content scanning"]
    }
  ];

  const newsItems = [
    { icon: AlertTriangle, title: "Phishing Attacks Increase by 300%", description: "New report shows phishing attacks have tripled in the past year. Stay protected with PhishGuard's advanced detection." },
    { icon: CheckCircle, title: "New AI Model Achieves 99.7% Accuracy", description: "Our latest machine learning model sets new standards in phishing detection accuracy." },
    { icon: TrendingUp, title: "Mobile Phishing on the Rise", description: "Smartphone users are now the primary target. Learn how to stay safe on mobile devices." }
  ];

  return (
    <div className="home-page">
      {/* Hero Section */}
      <section className="hero-section">
        <div className="hero-content">
          <h1 className="hero-title">
            Protect Yourself from <span className="highlight">Phishing Attacks</span>
          </h1>
          <p className="hero-subtitle">
            Advanced AI-powered phishing detection that identifies malicious websites in milliseconds. 
            Stay safe with the most accurate and fastest phishing detection system.
          </p>
          
          {/* Stats */}
          <div className="stats-grid">
            {stats.map((stat, index) => (
              <div key={index} className="stat-card">
                <stat.icon className="stat-icon" />
                <div className="stat-value">{stat.value}</div>
                <div className="stat-label">{stat.label}</div>
              </div>
            ))}
          </div>

          {/* CTA Button */}
          <button className="cta-button" onClick={() => setCurrentPage('services')}>
            <ArrowRight className="cta-icon" />
            Try Our Services
          </button>
        </div>
      </section>

      {/* Features Section */}
      <section className="features-section">
        <h2 className="section-title">Why Choose PhishGuard?</h2>
        <p className="features-subtitle">Click "Know More" to learn about each feature</p>
        <div className="features-grid">
          {features.map((feature, index) => (
            <div key={index} className="feature-card">
              <div className="feature-content">
                <feature.icon className="feature-icon" />
                <h3 className="feature-title">{feature.title}</h3>
                <p className="feature-short-desc">{feature.shortDesc}</p>
                <button 
                  className="know-more-btn"
                  onClick={() => setSelectedFeature(feature)}
                >
                  Know More
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Feature Detail Modal */}
      {selectedFeature && (
        <FeatureDetailModal 
          feature={selectedFeature} 
          onClose={() => setSelectedFeature(null)} 
        />
      )}

      {/* News Section */}
      <section className="news-section">
        <h2 className="section-title">Latest News & Updates</h2>
        <div className="news-grid">
          {newsItems.map((news, index) => (
            <div key={index} className="news-card">
              <news.icon className="news-icon" />
              <h3 className="news-title">{news.title}</h3>
              <p className="news-description">{news.description}</p>
              <span className="news-link">
                Read more <ArrowRight className="arrow-icon" />
              </span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

