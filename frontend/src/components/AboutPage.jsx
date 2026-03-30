import { ShieldCheck, Target, Users, Award, Globe, Lock, Zap } from "lucide-react";

// About Page Component
export default function AboutPage() {
  const teamMembers = [
    { 
      name: "Dr. Sarah Chen", 
      role: "CEO & Founder", 
      bio: "Former cybersecurity researcher with 15+ years of experience in threat detection and AI/ML systems.",
      icon: Users
    },
    { 
      name: "Michael Rodriguez", 
      role: "CTO", 
      bio: "Expert in distributed systems and real-time data processing, previously led engineering teams at major tech companies.",
      icon: Zap
    },
    { 
      name: "Emily Thompson", 
      role: "Head of AI/ML", 
      bio: "PhD in Machine Learning from MIT, specializes in anomaly detection and predictive security models.",
      icon: Target
    },
    { 
      name: "James Park", 
      role: "Head of Security", 
      bio: "Certified security professional with extensive experience in penetration testing and vulnerability assessment.",
      icon: Lock
    }
  ];

  const values = [
    {
      icon: ShieldCheck,
      title: "Security First",
      description: "We prioritize the security of our users above all else, implementing industry-leading protection measures."
    },
    {
      icon: Target,
      title: "Accuracy",
      description: "Our AI models achieve 99.7% accuracy, ensuring minimal false positives while catching real threats."
    },
    {
      icon: Lock,
      title: "Privacy",
      description: "We never store or share your data. Your privacy is protected with end-to-end encryption."
    },
    {
      icon: Globe,
      title: "Global Impact",
      description: "Protecting millions of users worldwide from phishing attacks and online threats."
    }
  ];

  const achievements = [
    { icon: Award, value: "50K+", label: "Threats Blocked" },
    { icon: Globe, value: "2M+", label: "URLs Scanned" },
    { icon: Users, value: "500K+", label: "Active Users" },
    { icon: Target, value: "99.7%", label: "Accuracy Rate" }
  ];

  return (
    <div className="about-page">
      {/* Mission Section */}
      <section className="about-hero">
        <div className="about-hero-content">
          <h1 className="about-hero-title">About PhishGuard</h1>
          <p className="about-hero-subtitle">
            Protecting the digital world from phishing attacks through advanced AI-powered detection technology.
            Our mission is to make the internet safer for everyone.
          </p>
        </div>
      </section>

      {/* Mission Statement */}
      <section className="mission-section">
        <h2 className="section-title">Our Mission</h2>
        <div className="mission-content">
          <div className="mission-text">
            <p>
              At PhishGuard, we believe everyone deserves to browse the internet safely. 
              Founded in 2020, we've dedicated ourselves to developing cutting-edge technology 
              that identifies and blocks phishing attempts before they can cause harm.
            </p>
            <p>
              Our team of cybersecurity experts and AI researchers works tirelessly to stay 
              ahead of evolving threats. We process millions of URLs daily, learning from 
              global threat intelligence to provide the most accurate protection available.
            </p>
            <p>
              We're not just building a product – we're creating a safer digital future 
              where phishing attacks become a thing of the past.
            </p>
          </div>
          <div className="mission-stats">
            {achievements.map((achievement, index) => (
              <div key={index} className="mission-stat-card">
                <achievement.icon className="mission-stat-icon" />
                <div className="mission-stat-value">{achievement.value}</div>
                <div className="mission-stat-label">{achievement.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Values Section */}
      <section className="values-section">
        <h2 className="section-title">Our Core Values</h2>
        <div className="values-grid">
          {values.map((value, index) => (
            <div key={index} className="value-card">
              <div className="value-icon">
                <value.icon />
              </div>
              <h3 className="value-title">{value.title}</h3>
              <p className="value-description">{value.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Team Section */}
      <section className="team-section">
        <h2 className="section-title">Meet Our Team</h2>
        <p className="team-subtitle">
          The experts behind PhishGuard's industry-leading protection
        </p>
        <div className="team-grid">
          {teamMembers.map((member, index) => (
            <div key={index} className="team-card">
              <div className="team-icon">
                <member.icon />
              </div>
              <h3 className="team-name">{member.name}</h3>
              <p className="team-role">{member.role}</p>
              <p className="team-bio">{member.bio}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Contact Section */}
      <section className="contact-section">
        <h2 className="section-title">Get in Touch</h2>
        <div className="contact-content">
          <div className="contact-info">
            <h3>Contact Information</h3>
            <p>
              <strong>Email:</strong> info@phishguard.com
            </p>
            <p>
              <strong>Phone:</strong> +1 (555) 123-4567
            </p>
            <p>
              <strong>Address:</strong> 123 Security Lane, Cyber City, CA 90210
            </p>
            <p>
              <strong>Support:</strong> support@phishguard.com (24/7)
            </p>
          </div>
          <div className="contact-hours">
            <h3>Business Hours</h3>
            <p><strong>Monday - Friday:</strong> 9:00 AM - 6:00 PM PST</p>
            <p><strong>Saturday:</strong> 10:00 AM - 4:00 PM PST</p>
            <p><strong>Sunday:</strong> Closed</p>
            <p><em>Note: Our automated threat detection systems operate 24/7.</em></p>
          </div>
        </div>
      </section>
    </div>
  );
}

