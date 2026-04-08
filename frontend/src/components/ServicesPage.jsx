import { useState } from "react";
import { useAuth } from "../contexts/AuthContext.jsx";
import { ShieldCheck, Globe, FileCheck, Search, Loader2, AlertCircle } from "lucide-react";

// Services Page Component
export default function ServicesPage() {
  // URL Scanner state
  const [urlInput, setUrlInput] = useState("");
  const [urlResult, setUrlResult] = useState(null);
  const [urlLoading, setUrlLoading] = useState(false);
  const [urlError, setUrlError] = useState(null);

  // Certificate Check state
  const [certInput, setCertInput] = useState("");
  const [certResult, setCertResult] = useState(null);
  const [certLoading, setCertLoading] = useState(false);
  const [certError, setCertError] = useState(null);

  // Domain Lookup state
  const [domainInput, setDomainInput] = useState("");
  const [domainResult, setDomainResult] = useState(null);
  const [domainModalVisible, setDomainModalVisible] = useState(false);
  const [domainLoading, setDomainLoading] = useState(false);
  const [domainError, setDomainError] = useState(null);

  const { token } = useAuth();

  const scanUrl = async () => {
    if (!urlInput) return;
    setUrlLoading(true);
    setUrlError(null);
    setUrlResult(null);

    try {
      const urlReq = { url: urlInput };
      const urlBody = JSON.stringify(urlReq);
      
      const response = await fetch("/api/url/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token && { "Authorization": `Bearer ${token}` }),
        },
        body: urlBody,
      });

      if (!response.ok) {
        throw new Error("Failed to scan URL");
      }

      const data = await response.json();
      console.log("🔍 URL API Response:", data); 
      setUrlResult({
        type: "url",
        result: data.result || "unknown",
        confidence: data.confidence || 0,
        message: data.message || "Complete",
      });
    } catch (err) {
      setUrlError(err.message);
    } finally {
      setUrlLoading(false);
    }
  };

  const checkCertificate = async () => {
    if (!certInput) return;
    setCertLoading(true);
    setCertError(null);
    setCertResult(null);

    try {
      let domain = certInput;
      try {
        const urlObj = new URL(certInput.startsWith("http") ? certInput : `https://${certInput}`);
        domain = urlObj.hostname;
      } catch (e) {
        // Use the input as-is
      }

      const certReq = { domain: domain };
      const certBody = JSON.stringify(certReq);
      
      const response = await fetch("/api/certificate/check", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token && { "Authorization": `Bearer ${token}` }),
        },
        body: certBody,
      });

      if (!response.ok) {
        throw new Error("Failed to check certificate");
      }

      const data = await response.json();    
      console.log("🔍 CERT API Response:", data); 
      setCertResult({
        type: "certificate",
        result: data.result || "unknown",
        confidence: data.confidence || 0,
        message: data.message || "Complete",
      });
    } catch (err) {
      setCertError(err.message);
    } finally {
      setCertLoading(false);
    }
  };

  const lookupDomain = async () => {
    if (!domainInput) return;

    setDomainLoading(true);
    setDomainError(null);
    setDomainResult(null);

    try {
      let domain = domainInput;

      // ✅ Extract clean domain
      try {
        const urlObj = new URL(
          domainInput.startsWith("http")
            ? domainInput
            : `https://${domainInput}`
        );
        domain = urlObj.hostname;
      } catch (e) {
        domain = domainInput.trim();
      }

      const response = await fetch("/api/domain/lookup", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token && { Authorization: `Bearer ${token}` }),
        },
        body: JSON.stringify({ domain }),
      });

      if (!response.ok) throw new Error("Failed to lookup domain");

      const data = await response.json();    
      console.log("🔍 DOMAIN API Response:", data);

      setDomainResult({
        type: "domain",
        result: data.result || "domain-valid",
        confidence: data.confidence || 0,
        message: data.message || "Analysis complete",
        details: data.details,
        ownership: data.ownership,
      });

    } catch (err) {
      setDomainError(err.message);
    } finally {
      setDomainLoading(false);
    }
  };

  const services = [
    { 
      id: "url",
      icon: Globe, 
      title: "URL Scanner", 
      description: "Scan and analyze any URL to detect phishing attempts and malicious websites",
      placeholder: "Enter website URL to scan",
      buttonText: "Scan URL",
      action: scanUrl,
      inputValue: urlInput,
      setInputValue: setUrlInput,
      result: urlResult,
      loading: urlLoading,
      error: urlError
    },
    { 
      id: "certificate",
      icon: FileCheck, 
      title: "Certificate Check", 
      description: "Verify SSL/TLS certificates to ensure secure connections and valid encryption",
      placeholder: "Enter domain to check certificate",
      buttonText: "Check Certificate",
      action: checkCertificate,
      inputValue: certInput,
      setInputValue: setCertInput,
      result: certResult,
      loading: certLoading,
      error: certError
    },
    { 
      id: "domain",
      icon: Search, 
      title: "Domain Lookup", 
      description: "Research domain registration details and ownership information",
      placeholder: "Enter domain to lookup",
      buttonText: "Lookup Domain",
      action: lookupDomain,
      inputValue: domainInput,
      setInputValue: setDomainInput,
      result: domainResult,
      loading: domainLoading,
      error: domainError
    }
  ];

  return (
    <div className="services-page">
      <section className="services-section">
        <h2 className="section-title">Our Services</h2>
        <p className="services-subtitle">
          Choose a security service below to get started with your phishing detection
        </p>
        
        <div className="services-grid">
          {services.map((service, index) => (
            <div key={index} className="service-card">
              <div className="service-icon">
                <service.icon />
              </div>
              <h3 className="service-title">{service.title}</h3>
              <p className="service-description">{service.description}</p>
              
              <div className="service-input-wrapper">
                <input
                  type="text"
                  placeholder={service.placeholder}
                  value={service.inputValue}
                  onChange={(e) => service.setInputValue(e.target.value)}
                  className="service-input"
                  disabled={service.loading}
                />
                <button 
                  onClick={service.action} 
                  className="service-button"
                  disabled={service.loading}
                >
                  {service.loading ? (
                    <>
                      <Loader2 className="animate-spin mr-2 h-4 w-4" />
                      Scanning...
                    </>
                  ) : (
                    service.buttonText
                  )}
                </button>
              </div>

              {service.error && (
                <div className="service-error">
                  Error: {service.error}
                </div>
              )}

              {/* NEW: Handle ML/Python errors */}
              {service.result && service.result.result === 'error' && (
                <div className="service-result result-error">
                  <AlertCircle className="result-icon" />
                  <div className="result-content">
                    Analysis Error: {service.result.message || 'ML processing failed'}
                  </div>
                  {service.result.confidence !== undefined && (
                    <div className="result-confidence">
                      Confidence: {service.result.confidence.toFixed(1)}%
                    </div>
                  )}
                </div>
              )}

              {service.result && service.result.result !== 'error' && !service.error && (
                <div
                  className={`service-result ${
                    service.result.result === 'safe' || service.result.result === 'certificate-valid' || service.result.result === 'domain-valid'
                      ? 'result-safe'
                      : 'result-danger'
                  }`}
                >
                  <ShieldCheck className="result-icon" />
                  <div className="result-content">
                    {service.result.result === 'safe' && 'Website Looks Safe'}
                    {service.result.result === 'phishing' && 'Phishing Website Detected'}
                    {service.result.result === 'certificate-valid' && 'Certificate is Valid'}
                    {service.result.result === 'certificate-invalid' && 'Certificate Issue Found'}
                    {service.result.result === 'domain-valid' && 'Domain Appears Legitimate'}
                    {service.result.result === 'domain-suspicious' && 'Domain Shows Suspicious Characteristics'}
                    {service.result.result === 'domain-invalid' && 'Invalid Domain'}
                  </div>
                  {service.result.confidence && (
                    <div className="result-confidence">
                      Confidence: {service.result.confidence.toFixed(1)}%
                    </div>
                  )}
                  {service.result.type === 'domain' && (
                    <button 
                      onClick={() => setDomainModalVisible(true)}
                      className="view-details-btn"
                    >
                      📊 View Full Details
                    </button>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* Domain Results Modal */}
      {domainModalVisible && domainResult && (
        <div className="domain-modal-overlay" onClick={() => setDomainModalVisible(false)}>
          <div className="domain-modal" onClick={(e) => e.stopPropagation()}>
            <div className="domain-modal-header">
              <h3>Domain Analysis Report</h3>
              <button className="modal-close-btn" onClick={() => setDomainModalVisible(false)}>
                ×
              </button>
            </div>
            <div className="domain-modal-body">
              <div className="domain-summary">
                <h4>{domainResult.message || 'Domain Analysis Complete'}</h4>
                <div className={`status-badge ${domainResult.result === 'domain-valid' ? 'safe' : 'danger'}`}>
                  {domainResult.result === 'domain-valid' ? 'Legitimate' : 'Suspicious'}
                </div>
              </div>
              
              {domainResult.details && (
                <div className="domain-section">
                  <h5>Domain Information</h5>
                  <div className="aligned-details-container">
                    {domainResult.details.domainAgeDays !== undefined && (
                      <div className="detail-row">
                        <span className="detail-label">Domain Age:</span>
                        <span className="detail-value">{domainResult.details.domainAgeDays} days {domainResult.details.isNewDomain && '(New Domain)'}</span>
                      </div>
                    )}
                    {domainResult.details.registrar && (
                      <div className="detail-row">
                        <span className="detail-label">Registrar:</span>
                        <span className="detail-value">{domainResult.details.registrar}</span>
                      </div>
                    )}
                    {domainResult.details.creationDate && (
                      <div className="detail-row">
                        <span className="detail-label">Created:</span>
                        <span className="detail-value">{domainResult.details.creationDate}</span>
                      </div>
                    )}
                    {domainResult.details.expiryDate && (
                      <div className="detail-row">
                        <span className="detail-label">Expires:</span>
                        <span className="detail-value">{domainResult.details.expiryDate}</span>
                      </div>
                    )}
                    {domainResult.details.countryName && (
                      <div className="detail-row">
                        <span className="detail-label">Registrant Country:</span>
                        <span className="detail-value">{domainResult.details.countryName}{domainResult.details.isHighRiskCountry && ' (High Risk)'}</span>
                      </div>
                    )}
                    {domainResult.details.nameServers && (
                      <div className="detail-row">
                        <span className="detail-label">Name Servers:</span>
                        <span className="detail-value">{domainResult.details.nameServers.slice(0, 3).join(', ')}{domainResult.details.nameServers.length > 3 && '...'}</span>
                      </div>
                    )}
                    {domainResult.details.hasPrivacyProtection !== undefined && (
                      <div className="detail-row">
                        <span className="detail-label">Privacy Protection:</span>
                        <span className="detail-value">{domainResult.details.hasPrivacyProtection ? 'Enabled' : 'None'}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
              
              {domainResult.ownership && (
                <div className="domain-section">
                  <h5>Ownership Information</h5>
                  <div className="aligned-details-container">
                    {domainResult.ownership.registrantName && (
                      <div className="detail-row">
                        <span className="detail-label">Registrant:</span>
                        <span className="detail-value">{domainResult.ownership.registrantName}</span>
                      </div>
                    )}
                    {domainResult.ownership.registrantOrganization && (
                      <div className="detail-row">
                        <span className="detail-label">Organization:</span>
                        <span className="detail-value">{domainResult.ownership.registrantOrganization}</span>
                      </div>
                    )}
                    {domainResult.ownership.registrantEmail && (
                      <div className="detail-row">
                        <span className="detail-label">Email:</span>
                        <span className="detail-value">{domainResult.ownership.registrantEmail}</span>
                      </div>
                    )}
                    {domainResult.ownership.registrantCountry && (
                      <div className="detail-row">
                        <span className="detail-label">Country:</span>
                        <span className="detail-value">{domainResult.ownership.registrantCountry}</span>
                      </div>
                    )}
                    {domainResult.ownership.isPrivacyProtected && (
                      <div className="detail-row warning">
                        <span className="detail-label">Privacy Notice:</span>
                        <span className="detail-value">Privacy protection enabled - details may be hidden</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
