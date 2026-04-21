import { useState } from "react";
import { useAuth } from "../contexts/AuthContext";
import { ShieldCheck, Globe, FileCheck, Search, Loader2, AlertCircle, AlertTriangle } from "lucide-react";

export default function ServicesPage() {
  const { token } = useAuth();

  // State for three services
  const [urlScan, setUrlScan] = useState({ url: '', loading: false, result: null, error: null });
  const [domainCheck, setDomainCheck] = useState({ domain: '', loading: false, result: null, error: null });
  const [certificateCheck, setCertificateCheck] = useState({ url: '', loading: false, result: null, error: null });

  // Helper to get confidence display class and text
  const getConfidenceDisplay = (confidence) => {
    if (confidence == null || isNaN(confidence)) return { className: 'confidence-unknown', text: 'N/A' };
    const conf = Number(confidence).toFixed(1);
    let className, label;
    if (conf <= 50) {
      className = 'confidence-low result-safe';
      label = `Safe (${conf}%)`;
    } else if (conf <= 70) {
      className = 'confidence-medium';
      label = `Medium Risk (${conf}%)`;
    } else {
      className = 'confidence-high result-danger';
      label = `High Risk (${conf}%)`;
    }
    return { className, text: label };
  };

  // Helper to extract error message from response
  const getErrorMessage = async (response) => {
    try {
      const errorData = await response.json();
      const firstError = Object.values(errorData)[0];
      return typeof firstError === 'string' ? firstError : errorData.message || 'Request failed';
    } catch {
      return `Request failed: ${response.status}`;
    }
  };

  // Full URL Phishing Scan
  const scanUrl = async () => {
    if (!urlScan.url.trim()) return;
    setUrlScan(prev => ({...prev, loading: true, error: null }));
    try {
      const response = await fetch('/api/url/scan', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json', 
          'Accept': 'application/json',
          'Authorization': `Bearer ${token || ''}` 
        },
        body: JSON.stringify({ url: urlScan.url.trim() })
      });
      if (!response.ok) {
        throw new Error(await getErrorMessage(response));
      }
      const data = await response.json();
      setUrlScan(prev => ({...prev, result: data, loading: false }));
    } catch (err) {
      setUrlScan(prev => ({...prev, error: err.message || 'Scan failed', loading: false }));
    }
  };

  // Domain lookup
  const lookupDomain = async () => {
    if (!domainCheck.domain.trim()) return;
    setDomainCheck(prev => ({...prev, loading: true, error: null }));
    try {
      const response = await fetch('/api/domain/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': `Bearer ${token || ''}` },
        body: JSON.stringify({ domain: domainCheck.domain.trim() })
      });
      if (!response.ok) {
        throw new Error(await getErrorMessage(response));
      }
      const data = await response.json();
      setDomainCheck(prev => ({...prev, result: data, loading: false }));
    } catch (err) {
      setDomainCheck(prev => ({...prev, error: err.message || 'Lookup failed', loading: false }));
    }
  };

  // Certificate check
  const checkCertificate = async () => {
    if (!certificateCheck.url.trim()) return;
    setCertificateCheck(prev => ({...prev, loading: true, error: null }));
    try {
      const response = await fetch('/api/certificate/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': `Bearer ${token || ''}` },
        body: JSON.stringify({ url: certificateCheck.url.trim() })
      });
      if (!response.ok) {
        throw new Error(await getErrorMessage(response));
      }
      const data = await response.json();
      setCertificateCheck(prev => ({...prev, result: data, loading: false }));
    } catch (err) {
      setCertificateCheck(prev => ({...prev, error: err.message || 'Certificate check failed', loading: false }));
    }
  };

  const services = [
    {
      id: 'url',
      title: 'URL Phishing Scan',
      desc: 'Full AI-powered phishing analysis with ML detection',
      icon: Search,
      state: urlScan,
      setState: setUrlScan,
      onScan: scanUrl,
      field: 'url',
      placeholder: 'Enter URL to scan (e.g. https://example.com)'
    },
    {
      id: 'domain',
      title: 'Domain Reputation Check',
      desc: 'WHOIS lookup, age verification and reputation scoring',
      icon: Globe,
      state: domainCheck,
      setState: setDomainCheck,
      onScan: lookupDomain,
      field: 'domain',
      placeholder: 'Enter domain only (e.g. google.com)'
    },
    {
      id: 'certificate',
      title: 'SSL Certificate Analysis',
      desc: 'Certificate validity, issuer trust and expiration check',
      icon: FileCheck,
      state: certificateCheck,
      setState: setCertificateCheck,
      onScan: checkCertificate,
      field: 'url',
      placeholder: 'Enter URL to check (e.g. https://google.com)'
    }
  ];

  const renderResult = (service) => {
    if (service.loading) {
      return (
        <div className="service-result">
          <Loader2 className="result-icon h-5 w-5 animate-spin" />
          <span>Scanning...</span>
        </div>
      );
    }

    if (service.error) {
      return (
        <div className="service-result result-danger">
          <AlertCircle className="result-icon" />
          <span>{service.error}</span>
        </div>
      );
    }

    if (service.result?.result === 'error') {
      return (
        <div className="service-result result-danger">
          <AlertTriangle className="result-icon" />
          <div>{service.result.message || 'Analysis Error'}</div>
          {service.result.confidence != null && (
            <div className={`result-confidence ${getConfidenceDisplay(service.result.confidence).className}`}>
              {getConfidenceDisplay(service.result.confidence).text}
            </div>
          )}
        </div>
      );
    }

    if (service.result) {
      const isSafe = ['safe', 'certificate-valid', 'domain-valid'].includes(service.result.result);
      return (
        <div className={`service-result ${isSafe ? 'result-safe' : 'result-danger'}`}>
          <ShieldCheck className="result-icon" />
          <div>{service.result.message || 'Scan Complete'}</div>
          {service.result.confidence != null && (
            <div className={`result-confidence ${getConfidenceDisplay(service.result.confidence).className}`}>
              Risk: {getConfidenceDisplay(service.result.confidence).text}
            </div>
          )}
        </div>
      );
    }

    return null;
  };

  return (
    <div className="services-page">
      <section className="services-section">
        <h2 className="section-title">Security Analysis Services</h2>
        <p className="services-subtitle">AI-Powered Phishing Protection - Analyze URLs and Domains Instantly</p>
        <div className="services-grid">
          {services.map((service) => (
            <div key={service.id} className="service-card">
              <div className="service-icon">
                <service.icon />
              </div>
              <h3 className="service-title">{service.title}</h3>
              <p className="service-description">{service.desc}</p>
              <div className="service-input-wrapper">
                <input
                  className="service-input"
                  placeholder={service.placeholder}
                  value={service.state[service.field] || ''}
                  onChange={(e) => service.setState(prev => ({
                    ...prev, 
                    [service.field]: e.target.value, 
                    result: null, 
                    error: null 
                  }))}
                />
                <button 
                  className="service-button" 
                  onClick={service.onScan} 
                  disabled={service.state.loading || !(service.state[service.field] || '').trim()}
                >
                  {service.state.loading ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Search className="h-4 w-4 mr-2" />
                      Analyze
                    </>
                  )}
                </button>
              </div>
              {renderResult(service.state)}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
