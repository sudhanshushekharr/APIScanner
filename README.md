# 🛡️ ApiScanner - Next-Generation AI-Powered API Security Assessment Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3+-blue.svg)](https://www.typescriptlang.org/)
[![Security](https://img.shields.io/badge/Security-AI%20Powered-red.svg)](https://github.com/your-username/ApiScanner)

> **Enterprise-grade API vulnerability scanner with real-time AI-powered risk analytics, interactive visualizations, and automated remediation guidance.**

## 🚀 Overview

ApiScanner is a cutting-edge API security assessment platform that combines advanced vulnerability scanning with AI-powered risk prediction and stunning real-time visualizations. Think of it as "Grammarly for API security" - it doesn't just find vulnerabilities, it provides intelligent insights and actionable remediation guidance.

### ✨ Key Features

- 🔍 **Intelligent Discovery**: Multi-method endpoint discovery (Swagger, crawling, brute-force, robots.txt)
- 🤖 **AI-Powered Analysis**: Machine learning models for vulnerability prediction and risk scoring
- 📊 **Real-Time Dashboard**: Interactive visualizations with live scan progress and risk heatmaps
- 🎯 **Comprehensive Testing**: 40+ vulnerability types covering OWASP API Top 10
- 📈 **Advanced Analytics**: CVSS scoring, risk categorization, and performance metrics
- 📄 **Smart Reporting**: AI-generated PDF reports with remediation guidance
- 🔄 **Real-Time Updates**: WebSocket-powered live updates and progress tracking
- 🎨 **Modern UI**: Glass morphism design with responsive, accessible interface
- 🤖 **Automation & Integration**: n8n workflows and webhook notifications
- 🔔 **Smart Notifications**: Automated alerts for critical vulnerabilities via Slack, Jira, and email

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │   AI/ML Engine  │
│                 │    │                 │    │                 │
│ • React/TS      │◄──►│ • Express.js    │◄──►│ • TensorFlow.js │
│ • D3.js         │    │ • Socket.io     │    │ • OpenAI API    │
│ • Chart.js      │    │ • SQLite/PostgreSQL│ │ • Custom Models │
│ • Glass Morphism│    │ • Winston Logger│    │ • Risk Scoring  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Core Modules  │
                    │                 │
                    │ • Discovery     │
                    │ • Security      │
                    │ • Visualization │
                    │ • Reports       │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Automation     │
                    │                 │
                    │ • n8n Workflows │
                    │ • Webhooks      │
                    │ • Notifications │
                    └─────────────────┘
```

## 🎯 What Makes ApiScanner Special?

### 🧠 **AI-Powered Intelligence**
- **Enhanced Risk Scoring**: ML models trained on real-world vulnerability data
- **Pattern Recognition**: Identifies complex attack vectors and business logic flaws
- **False Positive Reduction**: AI analysis reduces noise and improves accuracy
- **Predictive Analytics**: Forecasts potential security risks and attack vectors

### 🎨 **Stunning Visualizations**
- **Real-Time Network Maps**: Interactive API topology with risk-based coloring
- **Risk Heatmaps**: Visual endpoint risk assessment with zoom capabilities
- **Progress Timelines**: Beautiful phase-based scan progress tracking
- **Analytics Dashboards**: Comprehensive charts and metrics visualization

### 🔧 **Comprehensive Security Testing**

| Category | Tests | Coverage |
|----------|-------|----------|
| **Authentication** | 8 | JWT, OAuth, Basic Auth, API Keys |
| **Authorization** | 12 | RBAC, ABAC, Privilege Escalation |
| **Injection** | 6 | SQL, NoSQL, XSS, Command Injection |
| **Configuration** | 15 | Headers, CORS, TLS, CSP, HSTS |
| **Data Exposure** | 10 | PII, Sensitive Data, Information Disclosure |
| **Business Logic** | 5 | Rate Limiting, Race Conditions, Mass Assignment |

### 🤖 **Automation & Integration**

| Feature | Capabilities | Integrations |
|---------|-------------|--------------|
| **n8n Workflows** | Automated vulnerability response, ticket creation, notifications | Slack, Jira, Teams, Email |
| **Webhook Notifications** | Real-time alerts for critical findings | Custom webhooks, API endpoints |
| **Compliance Automation** | Automated regulatory reporting | SOC2, ISO27001, HIPAA, PCI DSS |

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ 
- npm or yarn
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/ApiScanner.git
cd ApiScanner

# Install dependencies
npm install

# Set up environment variables
cp config/env.example .env
# Edit .env with your configuration

# Start the development server
npm run dev
```

### Usage

1. **Start the Scanner**
   ```bash
   npm run dev
   ```

2. **Open the Dashboard**
   ```
   http://localhost:3000
   ```

3. **Configure Your Scan**
   - Enter target API URL
   - Select scan profile (Quick/Standard/Deep)
   - Choose discovery methods
   - Click "Launch Scan"

4. **Monitor Real-Time Progress**
   - Watch live endpoint discovery
   - View vulnerability detection in real-time
   - Analyze risk scores and CVSS metrics

5. **Generate Reports**
   - Export JSON/CSV data
   - Generate AI-powered PDF reports
   - Access remediation guidance

## 📊 Dashboard Features

### 🎛️ **Scan Configuration**
- **Target URL**: Support for any REST/GraphQL API
- **Scan Profiles**: Quick (5 min), Standard (15 min), Deep (30 min)
- **Discovery Methods**: Swagger, Crawling, Brute-force, GraphQL
- **Custom Settings**: Timeouts, concurrency, exclusions

### 📈 **Real-Time Analytics**
- **Endpoint Discovery**: Live tracking of found endpoints
- **Vulnerability Detection**: Real-time security findings
- **Risk Scoring**: AI-powered risk assessment
- **Performance Metrics**: Scan speed and efficiency tracking

### 🎨 **Interactive Visualizations**
- **Network Topology**: API structure with risk-based coloring
- **Risk Heatmap**: Endpoint vulnerability density
- **Progress Timeline**: Phase-based scan tracking
- **Analytics Charts**: Vulnerability distribution and trends

### 📋 **Comprehensive Results**
- **Endpoint Inventory**: Complete API surface mapping
- **Security Findings**: Detailed vulnerability reports
- **Remediation Guidance**: AI-generated fix recommendations
- **Compliance Status**: OWASP API Top 10 compliance checking

### 🤖 **Automation Features**
- **Smart Notifications**: Automatic alerts for critical/high vulnerabilities
- **Workflow Integration**: n8n workflows for automated response actions
- **Compliance Reporting**: Automated regulatory assessment reports

## 🔧 Advanced Configuration

### Environment Variables

```bash
# Server Configuration
PORT=3000
NODE_ENV=development

# Database
DATABASE_URL=sqlite://./data/security_scans.db
# or DATABASE_URL=postgresql://user:pass@localhost:5432/apiscanner

# AI/ML Configuration
OPENAI_API_KEY=your_openai_key
GROQ_API_KEY=your_groq_key
AI_CONFIDENCE_THRESHOLD=0.8

# Security
JWT_SECRET=your_jwt_secret
BCRYPT_ROUNDS=12

# Scanning
MAX_CONCURRENT_SCANS=5
DEFAULT_TIMEOUT=30000
MAX_ENDPOINTS_PER_SCAN=1000

# Automation & Integration
WEBHOOK_URL=https://your-n8n-instance.com/webhook/security-alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/your/slack/webhook
JIRA_WEBHOOK_URL=https://your-domain.atlassian.net/rest/api/3/issue
```

### Custom Scan Profiles

```typescript
const customProfile = {
  depth: 'comprehensive',
  includeAI: true,
  testTypes: [
    'auth',
    'injection', 
    'exposure',
    'config',
    'rate-limiting',
    'business-logic'
  ],
  maxEndpoints: 500,
  timeout: 60000,
  concurrent: true
};
```

### n8n Workflow Integration

```typescript
// Example n8n webhook payload for critical vulnerabilities
{
  "endpoint": "/api/users",
  "type": "SQL_INJECTION",
  "severity": "CRITICAL",
  "description": "SQL injection vulnerability detected",
  "scanId": "scan-12345",
  "timestamp": "2024-01-15T10:30:00Z",
  "recommendedActions": [
    "Implement input validation",
    "Use parameterized queries",
    "Add WAF protection"
  ]
}
```

## 🧪 Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run specific test suites
npm test -- --testNamePattern="discovery"
npm test -- --testNamePattern="security"
```

## 📚 API Documentation

### Core Endpoints

```typescript
// Start a new scan
POST /api/v1/scans
{
  "target": {
    "baseUrl": "https://api.example.com",
    "authMethod": "bearer",
    "authToken": "optional_token"
  },
  "configuration": {
    "depth": "comprehensive",
    "includeAI": true,
    "testTypes": ["auth", "injection", "exposure"]
  }
}

// Get scan results
GET /api/v1/scans/:scanId

// Generate reports
POST /api/v1/reports/:scanId
{
  "format": "pdf",
  "type": "executive"
}

// AI risk analysis
POST /api/v1/ml/risk-score
{
  "vulnerability": {
    "type": "SQL_INJECTION",
    "severity": "HIGH",
    "endpoint": "/api/users",
    "evidence": {...}
  }
}
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Fork and clone
git clone https://github.com/your-username/ApiScanner.git
cd ApiScanner

# Install dependencies
npm install

# Set up pre-commit hooks
npm run prepare

# Start development
npm run dev
```

### Project Structure

For a detailed overview of the project structure, see [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md).

- **`src/`** - Source code and core modules
- **`docs/`** - Documentation (technical, guides, presentations)
- **`tests/`** - Test files organized by functionality
- **`examples/`** - Example implementations and demos
- **`reports/`** - Generated scan reports and exports

### Code Style

```bash
# Lint code
npm run lint

# Format code
npm run format

# Type checking
npm run type-check
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OWASP API Security Top 10** for vulnerability categorization
- **D3.js** for stunning visualizations
- **TensorFlow.js** for AI/ML capabilities
- **Socket.io** for real-time communication
- **Chart.js** for analytics visualizations
- **n8n** for powerful workflow automation
- **Slack & Jira** for notification systems

## 📞 Support

- **Documentation**: [Wiki](https://github.com/your-username/ApiScanner/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-username/ApiScanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/ApiScanner/discussions)
- **Email**: support@apiscanner.dev

## 🚀 Roadmap

### v2.0 (Q2 2025)
- [ ] GraphQL schema analysis
- [ ] Advanced rate limiting detection
- [ ] Custom vulnerability signatures
- [ ] Team collaboration features
- [ ] CI/CD integration
- [x] n8n workflow automation
- [x] Smart notifications

### v2.1 (Q3 2025)
- [ ] Multi-language support
- [x] Advanced compliance reporting
- [ ] Threat intelligence integration
- [x] Automated remediation scripts
- [ ] API security training modules
- [ ] Advanced n8n workflow templates
- [ ] Multi-channel notification system

### v2.2 (Q4 2025)
- [ ] Cloud-native deployment
- [ ] Advanced ML models
- [ ] Real-time threat detection
- [ ] Integration marketplace
- [ ] Enterprise SSO support

---

<div align="center">

**Made with ❤️ by the SUSH**

[![GitHub stars](https://img.shields.io/github/stars/your-username/ApiScanner?style=social)](https://github.com/your-username/ApiScanner)
[![GitHub forks](https://img.shields.io/github/forks/your-username/ApiScanner?style=social)](https://github.com/your-username/ApiScanner)
[![GitHub issues](https://img.shields.io/github/issues/your-username/ApiScanner)](https://github.com/your-username/ApiScanner/issues)

**Securing APIs, one scan at a time! 🛡️**

</div> 