// Native crypto module wrapper
let nativeModule = null;

try {
    nativeModule = require('./build/Release/vault_crypto_native');
} catch (error) {
    // Native module not available - this is expected in development/CI environments
    console.warn('Native crypto module not available:', error.message);
}

module.exports = nativeModule;