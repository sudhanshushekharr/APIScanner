# 📁 ApiScanner Project Structure

This document provides a comprehensive overview of the ApiScanner project's organized file structure.

## 🏗️ Root Directory Structure

```
ApiScanner/
├── 📄 README.md                    # Main project documentation
├── 📦 package.json                 # Dependencies and scripts
├── ⚙️ tsconfig.json               # TypeScript configuration
├── 🔧 .env                        # Environment variables (local)
├── 🚫 .gitignore                  # Git ignore rules
├── 📋 .gitattributes             # Git attributes
├── 🗂️ .DS_Store                  # macOS system file
│
├── 📁 src/                        # Source code
│   ├── 🤖 ai/                     # AI/ML engines
│   ├── 🔧 core/                   # Core functionality
│   ├── 🔍 discovery/              # Endpoint discovery
│   ├── 🔗 integration/            # External integrations
│   ├── 💡 recommendations/        # Remediation recommendations
│   ├── 🛣️ routes/                # API routes
│   ├── 🛡️ security/              # Security testing modules
│   ├── 📝 types/                  # TypeScript type definitions
│   ├── 🛠️ utils/                 # Utility functions
│   ├── 📊 visualization/          # Dashboard visualization
│   └── 🚀 app.ts                  # Main application entry
│
├── 📁 docs/                       # Documentation
│   ├── 📖 technical/              # Technical documentation
│   ├── 🎯 guides/                 # User guides
│   ├── 🎤 presentations/          # Presentation materials
│   └── 📄 README.md               # Documentation index
│
├── 🧪 tests/                      # Test files
│   ├── 🔍 discovery/              # Discovery tests
│   ├── 🛡️ security/              # Security tests
│   ├── 🤖 ai/                     # AI/ML tests
│   ├── 📊 dashboard/              # Dashboard tests
│   ├── 🔧 integration/            # Integration tests
│   └── 📄 README.md               # Test documentation
│
├── 📁 examples/                   # Examples and demos
│   ├── 🚀 quick_start_dashboard.ts
│   ├── 📊 demo_visual_dashboard.ts
│   ├── 🔍 enhanced_discovery_test.ts
│   ├── 🎯 start_real_api_dashboard.ts
│   └── 📄 README.md               # Examples documentation
│
├── 📁 reports/                    # Generated reports
│   ├── 📊 cywayz-report-*.json    # Scan results
│   ├── 📊 cywayz-report-*.csv     # CSV exports
│   └── 📄 security-report-*.pdf   # PDF reports
│
├── 📁 public/                     # Static assets
│   ├── 🎨 dashboard.html          # Main dashboard
│   ├── 🏢 enterprise_dashboard.html
│   ├── 📊 real_api_dashboard.html
│   └── 📊 real_api_dashboard_revamped.html
│
├── 📁 config/                     # Configuration files
│   └── 📄 env.example             # Environment template
│
├── 📁 scripts/                    # Utility scripts
│   └── 🚀 simple_server.js        # Simple server script
│
├── 📁 dist/                       # Build output
├── 📁 data/                       # Database files
├── 📁 logs/                       # Application logs
├── 📁 cywayz/                     # Cywayz specific files
└── 📦 node_modules/               # Dependencies (not tracked)
```

## 📂 Detailed Directory Breakdown

### 🔧 **Source Code (`src/`)**
- **`ai/`** - AI/ML engines for risk scoring and vulnerability prediction
- **`core/`** - Core functionality (database, WebSocket)
- **`discovery/`** - Endpoint discovery engines (Swagger, crawling, brute-force)
- **`integration/`** - External service integrations
- **`recommendations/`** - Remediation guidance and recommendations
- **`routes/`** - API route handlers
- **`security/`** - Security testing modules (auth, injection, config)
- **`types/`** - TypeScript type definitions
- **`utils/`** - Utility functions and helpers
- **`visualization/`** - Dashboard visualization components

### 📚 **Documentation (`docs/`)**
- **`technical/`** - Technical implementation details, architecture docs
- **`guides/`** - User guides and integration instructions
- **`presentations/`** - Hackathon materials and presentation content

### 🧪 **Tests (`tests/`)**
- **Discovery tests** - Endpoint discovery functionality
- **Security tests** - Security scanning capabilities
- **AI/ML tests** - Machine learning model testing
- **Dashboard tests** - UI and visualization testing
- **Integration tests** - End-to-end functionality

### 🎯 **Examples (`examples/`)**
- **Quick start demos** - Fast setup examples
- **Visual dashboard demos** - UI demonstration scripts
- **Enhanced discovery** - Advanced discovery examples

### 📊 **Reports (`reports/`)**
- **JSON reports** - Structured scan results
- **CSV exports** - Data analysis exports
- **PDF reports** - Executive summaries

### 🎨 **Public Assets (`public/`)**
- **Dashboard HTML** - Main application interface
- **Enterprise dashboard** - Business-focused interface
- **Real-time dashboard** - Live scanning interface

## 🚀 Quick Navigation

### For New Developers
1. Start with `README.md` for project overview
2. Check `docs/guides/` for setup instructions
3. Review `examples/` for usage examples
4. Explore `src/` for code structure

### For Users
1. Read `README.md` for quick start
2. Check `docs/guides/` for detailed instructions
3. Use `examples/` for reference implementations

### For Contributors
1. Review `docs/technical/` for architecture
2. Check `tests/` for testing patterns
3. Follow the established directory structure
4. Update relevant documentation

## 📝 File Naming Conventions

### Source Files
- **TypeScript**: `camelCase.ts`
- **Routes**: `camelCase.ts`
- **Types**: `index.ts` (in types directory)

### Test Files
- **Pattern**: `test_<module>_<type>.ts`
- **Examples**: `test_discovery_direct.ts`, `test_security_framework.ts`

### Documentation
- **Technical**: `camelCase.md`
- **Guides**: `UPPER_CASE.md`
- **Presentations**: `presentation_*.md`

### Reports
- **Pattern**: `cywayz-report-<id>.{json|csv}`
- **PDFs**: `security-report-<id>.pdf`

## 🔧 Configuration

### Environment Variables
- **Local**: `.env` (not tracked)
- **Template**: `config/env.example`

### Build Output
- **Compiled**: `dist/`
- **Static**: `public/`

### Data Storage
- **Database**: `data/`
- **Logs**: `logs/`
- **Reports**: `reports/`

---

**Need help?** Check the main [README.md](README.md) for project overview and quick start instructions. 