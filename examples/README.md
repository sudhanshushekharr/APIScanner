# 🎯 ApiScanner Examples & Demos

This directory contains example implementations, demos, and quick start scripts for the ApiScanner project.

## 📁 Examples Structure

### 🚀 **Quick Start Examples**
- `quick_start_dashboard.ts` - Quick dashboard setup and configuration
- `start_real_api_dashboard.ts` - Real API dashboard startup script

### 📊 **Visual Dashboard Examples**
- `demo_visual_dashboard.ts` - Demo of visual dashboard capabilities
- `enhanced_discovery_test.ts` - Enhanced discovery with visualization

## 🎯 Usage Examples

### Quick Dashboard Setup
```typescript
// Using quick_start_dashboard.ts
import { startQuickDashboard } from './quick_start_dashboard';

startQuickDashboard({
  port: 3000,
  enableWebSocket: true,
  enableRealTimeUpdates: true
});
```

### Real API Dashboard
```typescript
// Using start_real_api_dashboard.ts
import { startRealApiDashboard } from './start_real_api_dashboard';

startRealApiDashboard({
  targetUrl: 'https://api.example.com',
  scanProfile: 'comprehensive',
  enableAI: true
});
```

### Visual Dashboard Demo
```typescript
// Using demo_visual_dashboard.ts
import { runVisualDemo } from './demo_visual_dashboard';

runVisualDemo({
  endpoints: ['/api/users', '/api/posts'],
  vulnerabilities: [
    { type: 'SQL_INJECTION', severity: 'HIGH' },
    { type: 'XSS', severity: 'MEDIUM' }
  ]
});
```

## 🔧 Running Examples

### Quick Start
```bash
# Quick dashboard
npx ts-node examples/quick_start_dashboard.ts

# Real API dashboard
npx ts-node examples/start_real_api_dashboard.ts

# Visual demo
npx ts-node examples/demo_visual_dashboard.ts
```

### Enhanced Discovery
```bash
# Enhanced discovery with visualization
npx ts-node examples/enhanced_discovery_test.ts
```

## 📊 Example Configurations

### Dashboard Configuration
```typescript
const dashboardConfig = {
  port: 3000,
  enableWebSocket: true,
  enableRealTimeUpdates: true,
  enableAI: true,
  scanProfiles: ['quick', 'standard', 'deep'],
  discoveryMethods: ['swagger', 'crawling', 'brute-force']
};
```

### Scan Configuration
```typescript
const scanConfig = {
  target: {
    baseUrl: 'https://api.example.com',
    authMethod: 'bearer',
    authToken: 'your-token'
  },
  configuration: {
    depth: 'comprehensive',
    includeAI: true,
    testTypes: ['auth', 'injection', 'exposure']
  }
};
```

## 🎨 Customization

### Custom Dashboard Themes
```typescript
const customTheme = {
  primaryColor: '#667eea',
  secondaryColor: '#764ba2',
  backgroundColor: '#0f0f23',
  glassMorphism: true
};
```

### Custom Scan Profiles
```typescript
const customProfile = {
  name: 'enterprise',
  depth: 'deep',
  timeout: 120000,
  maxEndpoints: 1000,
  includeAI: true,
  testTypes: ['auth', 'injection', 'exposure', 'config', 'business-logic']
};
```

## 📝 Contributing Examples

When adding new examples:
1. Follow the naming convention: `example_<purpose>.ts`
2. Include comprehensive comments
3. Add configuration examples
4. Update this README.md

### Example Template
```typescript
/**
 * Example: [Purpose]
 * Description: [What this example demonstrates]
 * Usage: [How to use this example]
 */

import { ApiScanner } from '../src';

export function runExample() {
  // Example implementation
}

// Configuration examples
export const exampleConfig = {
  // Configuration options
};
```

---

**Need help?** Check the main [README.md](../README.md) for project overview and the [docs/](../docs/) directory for detailed documentation. 