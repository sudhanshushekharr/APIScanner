# 🧪 ApiScanner Tests

This directory contains all test files for the ApiScanner project, organized by functionality.

## 📁 Test Structure

### 🔍 **Discovery Tests**
- `test_discovery_direct.ts` - Direct endpoint discovery testing
- `test_discovery.js` - JavaScript discovery tests

### 🛡️ **Security Tests**
- `test_security_framework.ts` - Core security framework testing
- `test_misconfiguration_direct.ts` - Misconfiguration detection tests
- `test_parameter_vulnerability_direct.ts` - Parameter vulnerability scanning tests

### 🤖 **AI/ML Tests**
- `test_ai_risk_scoring.ts` - AI risk scoring engine tests
- `test_enhanced_ml_engine.ts` - Enhanced ML engine testing
- `test_enhanced_ml_simple.ts` - Simplified ML tests

### 📊 **Dashboard Tests**
- `test_dashboard_integration.ts` - Dashboard integration testing
- `test_visual_dashboard.ts` - Visual dashboard functionality tests
- `test_visual_dashboard_fixed.ts` - Fixed visual dashboard tests
- `test_standalone_dashboard.ts` - Standalone dashboard testing

### 🔧 **Integration Tests**
- `test_real_api_scanner.ts` - Real API scanner integration tests
- `test_real_apis.js` - JavaScript API integration tests

### 🧪 **Framework Tests**
- `test_minimal_fixed.ts` - Minimal framework tests
- `test_parameter_vulnerability_direct.ts` - Parameter testing framework

## 🚀 Running Tests

### Run All Tests
```bash
npm test
```

### Run Tests in Watch Mode
```bash
npm run test:watch
```

### Run Specific Test Categories
```bash
# Discovery tests
npm test -- --testNamePattern="discovery"

# Security tests
npm test -- --testNamePattern="security"

# AI/ML tests
npm test -- --testNamePattern="ai|ml"

# Dashboard tests
npm test -- --testNamePattern="dashboard"
```

### Run Individual Test Files
```bash
# TypeScript tests
npx jest tests/test_discovery_direct.ts

# JavaScript tests
npx jest tests/test_discovery.js
```

## 📝 Writing Tests

### Test File Naming Convention
- `test_<module>_<type>.ts` - TypeScript tests
- `test_<module>_<type>.js` - JavaScript tests

### Test Structure
```typescript
describe('Module Name', () => {
  beforeEach(() => {
    // Setup
  });

  afterEach(() => {
    // Cleanup
  });

  it('should perform expected behavior', () => {
    // Test implementation
  });
});
```

## 🔧 Test Configuration

Tests are configured in:
- `package.json` - Jest configuration
- `tsconfig.json` - TypeScript configuration for tests
- `.jest.config.js` - Jest-specific settings (if exists)

## 📊 Test Coverage

To generate coverage reports:
```bash
npm test -- --coverage
```

Coverage reports will be generated in the `coverage/` directory.

---

**Need help?** Check the main [README.md](../README.md) for project overview and the [docs/](../docs/) directory for detailed documentation. 