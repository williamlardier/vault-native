# Native Crypto Module for Vault

This document describes the high-performance native crypto module for Vault authentication operations.

## Overview

The native crypto module provides significant performance improvements for authentication operations by:

1. **Combining operations**: Decrypt + signature verification in a single native call
2. **Reducing serialization overhead**: Minimizing data transfers between JS and C++
3. **Leveraging OpenSSL optimizations**: Using highly optimized crypto implementations
4. **Caching plaintext keys**: Avoiding repeated decryption operations

## Performance Benefits

Based on benchmarks, the native module provides:
- **3-5x improvement** for crypto operations (HKDF + AES-GCM)
- **2-3x improvement** for HMAC operations (AWS v4 signature verification)
- **Reduced GC pressure** from fewer temporary objects
- **Better CPU cache utilization** in native code

## Architecture

```
┌─────────────────────┐
│ AuthOptimizedNative │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐    ┌──────────────────────┐
│ NativeCryptoHandler │───▶│ SecretKeyPlaintextCache │
└─────────┬───────────┘    └──────────────────────┘
          │
          ▼
┌─────────────────────┐    ┌──────────────────────┐
│ Native C++ Module   │    │ JavaScript Fallback  │
│ (vault_crypto_native)│◄──│ (existing crypto)    │
└─────────────────────┘    └──────────────────────┘
```

## Building the Native Module

### Prerequisites

- Node.js 16+ with development headers
- Python 3.x
- C++ compiler (GCC 7+, Clang 3.4+, or MSVC 2019+)
- OpenSSL development libraries

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install build-essential python3 libssl-dev
```

#### CentOS/RHEL
```bash
sudo yum groupinstall "Development Tools"
sudo yum install python3 openssl-devel
```

#### macOS
```bash
xcode-select --install
brew install openssl
```

### Building

1. Navigate to the native module directory:
```bash
cd native/
```

2. Install dependencies:
```bash
npm install
```

3. Build the native module:
```bash
npm run build
```

4. Test the module:
```bash
npm test
```

## Configuration

### Environment Variables

- `VAULT_USE_NATIVE_CRYPTO=true` - Enable native crypto module
- `VAULT_AUTH_OPTIMIZE_NATIVE=true` - Use native optimization in auth flow
- `VAULT_SECRET_KEY_CACHE_SIZE=10000` - Secret key cache size (default: 10000)
- `VAULT_SECRET_KEY_CACHE_TTL=3600` - Secret key cache TTL in seconds (default: 3600)

### Integration

The native module integrates seamlessly with existing code:

```javascript
// In your main application
const AuthHandler = require('./lib/Handlers/AuthOptimizedEnhanced');

// Use the enhanced handler which automatically chooses the best optimization
app.use('/auth', (req, res, next) => {
    AuthHandler.verifySignatureV4(vaultRequest, callback, service);
});
```

## Fallback Strategy

The implementation provides automatic fallback:

1. **Native crypto** (if available and enabled)
2. **MGET optimization** (existing optimization)
3. **Cache optimization** (existing optimization)  
4. **Standard implementation** (original code)

This ensures the system continues to work even if:
- Native module fails to compile
- Native module encounters runtime errors
- Environment variables disable optimizations

## Security Considerations

### Memory Management
- **Automatic cleanup**: Sensitive data is cleared from memory after use
- **Secure random**: Uses OpenSSL's secure random number generator
- **Constant-time operations**: Uses OpenSSL's constant-time implementations

### Cache Security
- **TTL expiration**: Cached keys automatically expire
- **Memory clearing**: Keys are overwritten with random data before deletion
- **Process isolation**: Cache is isolated to the process
- **Graceful shutdown**: Caches are cleared on process exit

### Threat Model
The native module maintains the same security properties as the existing implementation:
- Master key must be protected (same as before)
- Process memory access is equivalent threat
- Network and storage security unchanged

## Monitoring

### Cache Statistics

```javascript
const AuthHandler = require('./lib/Handlers/AuthOptimizedEnhanced');

// Get cache statistics
const stats = AuthHandler.getCacheStats();
console.log('Cache hit rate:', stats.native.hitRate);
console.log('Cache size:', stats.native.size);
```

### Performance Metrics
- Cache hit/miss ratios
- Native vs fallback usage
- Operation latencies
- Memory usage

## Troubleshooting

### Common Build Issues

1. **Missing OpenSSL headers**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libssl-dev
   
   # CentOS/RHEL
   sudo yum install openssl-devel
   
   # macOS
   brew install openssl
   export LDFLAGS="-L$(brew --prefix openssl)/lib"
   export CPPFLAGS="-I$(brew --prefix openssl)/include"
   ```

2. **Node.js headers missing**
   ```bash
   npm install --production=false
   ```

3. **Python version issues**
   ```bash
   npm config set python python3
   ```

### Runtime Issues

1. **Module not loading**: Check environment variables and file permissions

2. **Performance not improving**: Verify native module is actually being used:
   ```javascript
   const NativeCryptoHandler = require('./lib/Crypto/NativeCryptoHandler');
   console.log('Native available:', NativeCryptoHandler.isNativeAvailable());
   ```

3. **Memory leaks**: The module includes automatic cleanup, but monitor memory usage in production

### Debugging

Enable debug logging:
```bash
export DEBUG=vault:crypto:*
```

Check system logs for native module errors:
```bash
# Linux
journalctl -f | grep vault

# macOS
log stream --predicate 'process == "node"'
```

## Deployment

### Production Considerations

1. **Build in CI/CD**: Pre-compile the native module in your build pipeline
2. **Fallback testing**: Test that fallback works when native module is unavailable
3. **Monitoring**: Monitor cache hit rates and performance metrics
4. **Gradual rollout**: Use feature flags to gradually enable native optimization

### Docker Deployment

```dockerfile
FROM node:18-alpine

# Install build dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    openssl-dev

# Copy source
COPY . /app
WORKDIR /app

# Build native module
RUN cd native && npm install && npm run build

# Install production dependencies
RUN npm ci --only=production

# Enable native crypto
ENV VAULT_USE_NATIVE_CRYPTO=true
ENV VAULT_AUTH_OPTIMIZE_NATIVE=true

CMD ["node", "index.js"]
```

## Contributing

When modifying the native module:

1. **Test both sync and async paths**
2. **Verify fallback behavior**
3. **Check memory cleanup**
4. **Update documentation**
5. **Run security tests**

### Testing

```bash
# Run all tests
npm test

# Run only native tests
cd native && npm test

# Run security tests
npm run test:security
```
