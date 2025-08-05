// Suggested improvement to add caching to native path:

static _useNative(vaultRequest, accessKeyId, encryptedData, signatureData, callback) {
    const log = vaultRequest.getLog();
    
    // OPTIMIZATION: Check cache first if caching is enabled
    if (VAULT_SECRET_KEY_CACHE_ENABLED) {
        const SecretKeyHandler = require('../Handlers/SecretKey');
        
        // Try to get from cache first
        return SecretKeyHandler.getSecretKeyPlaintextById(vaultRequest, accessKeyId, (err, keyInstance) => {
            if (!err && keyInstance) {
                // Cache hit! Just verify signature without decryption
                log.debug('NativeCryptoHandler: Using cached secret key', { accessKeyId });
                
                const secretKey = keyInstance.getValue();
                return NativeCryptoHandler._verifySignatureOnly(secretKey, signatureData, (verifyErr, isValid) => {
                    if (verifyErr) return callback(verifyErr);
                    
                    if (!isValid) {
                        return callback(errors.SignatureDoesNotMatch);
                    }
                    
                    return callback(null, {
                        secretKey,
                        signatureValid: true,
                        fromCache: true,  // ← Indicate this came from cache
                        native: false     // ← Signature verification was JS, not native
                    });
                });
            }
            
            // Cache miss - proceed with native decrypt+verify
            log.debug('NativeCryptoHandler: Cache miss, using native decrypt+verify', { accessKeyId });
            
            // Your existing native crypto code here...
            let masterKey = Buffer.from(MasterKey.instance.get(), 'utf8');
            // ... rest of your existing code
        });
    }
    
    // Caching disabled - use native crypto directly (your existing code)
    // ... your existing implementation
}