#include <napi.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <atomic>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#ifdef __linux__
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#endif

// Secure memory management for sensitive data
class SecureBuffer {
private:
    void* data_;
    size_t size_;
    bool locked_;
    
public:
    SecureBuffer(size_t size) : size_(size), locked_(false) {
        // Allocate page-aligned memory for mlock compatibility
        #ifdef __linux__
        size_t page_size = getpagesize();
        size_t aligned_size = ((size + page_size - 1) / page_size) * page_size;
        data_ = aligned_alloc(page_size, aligned_size);
        #else
        data_ = malloc(size);
        #endif
        
        if (!data_) {
            throw std::bad_alloc();
        }
        
        // Zero the memory immediately
        OPENSSL_cleanse(data_, size_);
        
        #ifdef __linux__
        // Lock memory to prevent swapping to disk
        if (mlock(data_, size_) == 0) {
            locked_ = true;
        }
        // Note: We don't throw on mlock failure as it might not have permissions
        // but we track the state for cleanup
        #endif
    }
    
    ~SecureBuffer() {
        if (data_) {
            // Always clear sensitive data first
            OPENSSL_cleanse(data_, size_);
            
            #ifdef __linux__
            if (locked_) {
                munlock(data_, size_);
            }
            #endif
            
            free(data_);
            data_ = nullptr;
        }
    }
    
    // Disable copy and assignment
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    // Enable move semantics
    SecureBuffer(SecureBuffer&& other) noexcept 
        : data_(other.data_), size_(other.size_), locked_(other.locked_) {
        other.data_ = nullptr;
        other.size_ = 0;
        other.locked_ = false;
    }
    
    void* get() const { return data_; }
    size_t size() const { return size_; }
    bool is_locked() const { return locked_; }
    
    // Secure write operation
    void write(const void* src, size_t len) {
        if (len > size_) {
            throw std::out_of_range("Write exceeds buffer size");
        }
        memcpy(data_, src, len);
        // Clear any remaining space
        if (len < size_) {
            OPENSSL_cleanse(static_cast<char*>(data_) + len, size_ - len);
        }
    }
};

// Secure string that uses locked memory
using SecureString = std::basic_string<char, std::char_traits<char>, 
    std::allocator<char>>; // For now, we'll use a simple approach

// Initialize process security settings
void initializeProcessSecurity() {
    #ifdef __linux__
    // Disable core dumps to prevent memory dumps
    prctl(PR_SET_DUMPABLE, 0);
    
    // Set a recognizable process name for audit trails
    prctl(PR_SET_NAME, "vault-crypto");
    #endif
}

// Cache entry for storing decrypted secret keys
struct CacheEntry {
    std::vector<uint8_t> secretKey;
    std::chrono::steady_clock::time_point expiry;
    
    CacheEntry(const std::vector<uint8_t>& key, std::chrono::seconds ttl) 
        : secretKey(key), expiry(std::chrono::steady_clock::now() + ttl) {}
    
    ~CacheEntry() {
        // Secure cleanup
        OPENSSL_cleanse(secretKey.data(), secretKey.size());
    }
    
    bool isExpired() const {
        return std::chrono::steady_clock::now() >= expiry;
    }
};

// Thread-safe cache for secret keys
class SecretKeyCache {
private:
    std::unordered_map<std::string, std::unique_ptr<CacheEntry>> cache_;
    mutable std::mutex mutex_;  // mutable so it can be locked in const methods
    size_t maxSize_;
    std::chrono::seconds defaultTtl_;
    
public:
    SecretKeyCache(size_t maxSize = 10000, std::chrono::seconds ttl = std::chrono::seconds(3600)) 
        : maxSize_(maxSize), defaultTtl_(ttl) {}
    
    ~SecretKeyCache() {
        clear();
    }
    
    // Generate cache key from parameters
    std::string generateKey(const std::string& salt, const std::string& info, 
                           const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& tag) {
        // Create a unique key based on the encrypted data parameters
        std::string key = salt + "|" + info + "|";
        key.append(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
        key.append(reinterpret_cast<const char*>(tag.data()), tag.size());
        return key;
    }
    
    // Try to get cached secret key
    bool get(const std::string& cacheKey, std::vector<uint8_t>& secretKey) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = cache_.find(cacheKey);
        if (it == cache_.end()) {
            return false; // Cache miss
        }
        
        if (it->second->isExpired()) {
            cache_.erase(it);
            return false; // Expired
        }
        
        secretKey = it->second->secretKey;
        return true; // Cache hit
    }
    
    // Store secret key in cache
    void put(const std::string& cacheKey, const std::vector<uint8_t>& secretKey) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Remove expired entries and enforce size limit
        cleanup();
        
        if (cache_.size() >= maxSize_) {
            // Simple eviction: remove first entry (could be improved with LRU)
            cache_.erase(cache_.begin());
        }
        
        cache_[cacheKey] = std::make_unique<CacheEntry>(secretKey, defaultTtl_);
    }
    
    // Clear all entries
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        cache_.clear();
    }
    
    // Clean up expired entries
    void cleanup() {
        auto it = cache_.begin();
        while (it != cache_.end()) {
            if (it->second->isExpired()) {
                it = cache_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    // Get cache statistics
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cache_.size();
    }
};

// Global cache instance
static SecretKeyCache g_secretKeyCache;

// Cache hit/miss counters for debugging
static std::atomic<size_t> g_cacheHits{0};
static std::atomic<size_t> g_cacheMisses{0};
static std::atomic<size_t> g_cacheStores{0};

// Simple base64 decoder using OpenSSL
std::vector<uint8_t> decodeBase64(const std::string& base64) {
    BIO *bio, *b64;
    std::vector<uint8_t> result(base64.length());
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(base64.c_str(), base64.length());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    int decoded_size = BIO_read(bio, result.data(), base64.length());
    BIO_free_all(bio);
    
    if (decoded_size > 0) {
        result.resize(decoded_size);
    } else {
        result.clear();
    }
    
    return result;
}

// Forward declaration and core implementation
struct CryptoResult {
    bool success;
    bool signatureValid;
    std::vector<uint8_t> plaintext;
    std::string errorMessage;
};

CryptoResult performDecryptAndVerify(const std::string& masterKey,
                                   const std::string& salt,
                                   const std::string& info,
                                   const std::vector<uint8_t>& ciphertext,
                                   const std::vector<uint8_t>& tag,
                                   const std::string& stringToSign,
                                   const std::string& region,
                                   const std::string& service,
                                   const std::string& scopeDate,
                                   const std::string& expectedSignature) {
    CryptoResult result = {false, false, {}, ""};
    
    try {
        // Try cache first
        std::string cacheKey = g_secretKeyCache.generateKey(salt, info, ciphertext, tag);
        std::vector<uint8_t> cachedSecretKey;
        
        if (g_secretKeyCache.get(cacheKey, cachedSecretKey)) {
            // Cache hit! Skip decryption, just verify signature
            g_cacheHits.fetch_add(1);
            result.plaintext = cachedSecretKey;
            
            // AWS v4 signature verification using cached secret key
            SecureBuffer secretKeyBuf(cachedSecretKey.size());
            secretKeyBuf.write(cachedSecretKey.data(), cachedSecretKey.size());
            std::string secretKey(static_cast<char*>(secretKeyBuf.get()), cachedSecretKey.size());
            
            // AWS signature verification (same as below)
            auto hmacSha256 = [](const std::vector<uint8_t>& key, const std::string& data) -> std::vector<uint8_t> {
                std::vector<uint8_t> result(32);
                unsigned int len = 32;
                HMAC(EVP_sha256(), key.data(), key.size(),
                     reinterpret_cast<const unsigned char*>(data.c_str()), data.length(),
                     result.data(), &len);
                return result;
            };
            
            auto hmacSha256Str = [&hmacSha256](const std::string& key, const std::string& data) -> std::vector<uint8_t> {
                return hmacSha256(std::vector<uint8_t>(key.begin(), key.end()), data);
            };
            
            auto toHex = [](const std::vector<uint8_t>& data) -> std::string {
                std::string hex;
                hex.reserve(data.size() * 2);
                for (uint8_t byte : data) {
                    char buf[3];
                    snprintf(buf, sizeof(buf), "%02x", byte);
                    hex += buf;
                }
                return hex;
            };
            
            // AWS4-HMAC-SHA256 signing key derivation
            std::string kSecret = "AWS4" + secretKey;
            std::vector<uint8_t> kDate = hmacSha256Str(kSecret, scopeDate);
            std::vector<uint8_t> kRegion = hmacSha256(kDate, region);
            std::vector<uint8_t> kService = hmacSha256(kRegion, service.empty() ? "s3" : service);
            std::vector<uint8_t> kSigning = hmacSha256(kService, "aws4_request");
            std::vector<uint8_t> signature = hmacSha256(kSigning, stringToSign);
            
            std::string calculatedSignature = toHex(signature);
            result.signatureValid = (calculatedSignature == expectedSignature);
            result.success = true;
            
            return result;
        }
        
        // Cache miss - perform full decryption
        g_cacheMisses.fetch_add(1);
        
        // Step 1: HKDF key derivation
        std::vector<uint8_t> keyMaterial(44); // 32 bytes key + 12 bytes IV
        
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (!pctx) {
            result.errorMessage = "Failed to create HKDF context";
            return result;
        }

        if (EVP_PKEY_derive_init(pctx) <= 0 ||
            EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_salt(pctx, 
                reinterpret_cast<const unsigned char*>(salt.c_str()), 
                salt.length()) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_key(pctx,
                reinterpret_cast<const unsigned char*>(masterKey.c_str()),
                masterKey.length()) <= 0 ||
            EVP_PKEY_CTX_add1_hkdf_info(pctx,
                reinterpret_cast<const unsigned char*>(info.c_str()),
                info.length()) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            result.errorMessage = "Failed to setup HKDF parameters";
            return result;
        }

        size_t outlen = keyMaterial.size();
        if (EVP_PKEY_derive(pctx, keyMaterial.data(), &outlen) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            result.errorMessage = "HKDF derivation failed";
            return result;
        }
        EVP_PKEY_CTX_free(pctx);

        // Extract key and IV using secure buffers
        SecureBuffer key(32);
        SecureBuffer iv(12);
        key.write(keyMaterial.data(), 32);
        iv.write(keyMaterial.data() + 32, 12);
        
        // Clear the key material immediately
        OPENSSL_cleanse(keyMaterial.data(), keyMaterial.size());

        // Step 2: AES-GCM decryption
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            result.errorMessage = "Failed to create cipher context";
            return result;
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, 
                              static_cast<const uint8_t*>(key.get()), 
                              static_cast<const uint8_t*>(iv.get())) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            result.errorMessage = "Failed to initialize AES-GCM decryption";
            return result;
        }

        // Set expected tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), 
                               const_cast<uint8_t*>(tag.data())) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            result.errorMessage = "Failed to set GCM tag";
            return result;
        }

        // Decrypt
        result.plaintext.resize(ciphertext.size());
        int len;
        if (EVP_DecryptUpdate(ctx, result.plaintext.data(), &len, 
                             ciphertext.data(), ciphertext.size()) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            result.errorMessage = "Decryption update failed";
            return result;
        }

        int finalLen;
        if (EVP_DecryptFinal_ex(ctx, result.plaintext.data() + len, &finalLen) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            result.errorMessage = "Decryption verification failed - invalid tag or corrupted data";
            return result;
        }

        result.plaintext.resize(len + finalLen);
        EVP_CIPHER_CTX_free(ctx);

        // ✅ CACHE IMMEDIATELY AFTER SUCCESSFUL DECRYPTION (before signature verification)
        // This ensures we cache the expensive HKDF+AES-GCM work even if signature fails
        g_secretKeyCache.put(cacheKey, result.plaintext);
        g_cacheStores.fetch_add(1);

        // Note: key and iv SecureBuffers will automatically clear themselves when destructed

        // Step 3: AWS v4 signature verification using secure memory
        SecureBuffer secretKeyBuf(result.plaintext.size());
        secretKeyBuf.write(result.plaintext.data(), result.plaintext.size());
        std::string secretKey(static_cast<char*>(secretKeyBuf.get()), result.plaintext.size());
        
        // Helper functions for AWS signature calculation
        auto hmacSha256 = [](const std::vector<uint8_t>& key, const std::string& data) -> std::vector<uint8_t> {
            std::vector<uint8_t> result(32);
            unsigned int len = 32;
            HMAC(EVP_sha256(), key.data(), key.size(),
                 reinterpret_cast<const unsigned char*>(data.c_str()), data.length(),
                 result.data(), &len);
            return result;
        };
        
        auto hmacSha256Str = [&hmacSha256](const std::string& key, const std::string& data) -> std::vector<uint8_t> {
            return hmacSha256(std::vector<uint8_t>(key.begin(), key.end()), data);
        };
        
        auto toHex = [](const std::vector<uint8_t>& data) -> std::string {
            std::string hex;
            hex.reserve(data.size() * 2);
            for (uint8_t byte : data) {
                char buf[3];
                snprintf(buf, sizeof(buf), "%02x", byte);
                hex += buf;
            }
            return hex;
        };
        
        // AWS4-HMAC-SHA256 signing key derivation
        std::string kSecret = "AWS4" + secretKey;
        std::vector<uint8_t> kDate = hmacSha256Str(kSecret, scopeDate);
        std::vector<uint8_t> kRegion = hmacSha256(kDate, region);
        std::vector<uint8_t> kService = hmacSha256(kRegion, service.empty() ? "s3" : service);
        std::vector<uint8_t> kSigning = hmacSha256(kService, "aws4_request");
        std::vector<uint8_t> signature = hmacSha256(kSigning, stringToSign);
        
        std::string calculatedSignature = toHex(signature);
        result.signatureValid = (calculatedSignature == expectedSignature);

        // Note: secretKeyBuf will automatically clear the secret key when destructed
        result.success = true;
        
        // NOTE: Caching already done immediately after decryption above
        
    } catch (const std::exception& e) {
        result.errorMessage = e.what();
    }
    
    return result;
}

class VaultCryptoWorker : public Napi::AsyncWorker {
public:
    VaultCryptoWorker(Napi::Function callback,
                      const std::string& masterKey,
                      const std::string& salt,
                      const std::string& info,
                      const std::vector<uint8_t>& ciphertext,
                      const std::vector<uint8_t>& tag,
                      const std::string& stringToSign,
                      const std::string& region,
                      const std::string& service,
                      const std::string& scopeDate,
                      const std::string& expectedSignature)
        : Napi::AsyncWorker(callback),
          masterKey_(masterKey),
          salt_(salt),
          info_(info),
          ciphertext_(ciphertext),
          tag_(tag),
          stringToSign_(stringToSign),
          region_(region),
          service_(service),
          scopeDate_(scopeDate),
          expectedSignature_(expectedSignature),
          signatureValid_(false) {}

    void Execute() override {
        CryptoResult result = performDecryptAndVerify(masterKey_, salt_, info_, ciphertext_, tag_,
                                                     stringToSign_, region_, service_, scopeDate_, expectedSignature_);
        
        if (!result.success) {
            SetError(result.errorMessage);
            return;
        }
        
        plaintext_ = result.plaintext;
        signatureValid_ = result.signatureValid;
    }

    void OnOK() override {
        Napi::HandleScope scope(Env());
        
        Napi::Object result = Napi::Object::New(Env());
        result.Set("signatureValid", Napi::Boolean::New(Env(), signatureValid_));
        
        if (signatureValid_) {
            // Only return plaintext if signature is valid
            result.Set("secretKey", Napi::Buffer<uint8_t>::Copy(Env(), plaintext_.data(), plaintext_.size()));
        }

        Callback().Call({Env().Null(), result});
    }

private:
    std::string masterKey_;
    std::string salt_;
    std::string info_;
    std::vector<uint8_t> ciphertext_;
    std::vector<uint8_t> tag_;
    std::string stringToSign_;
    std::string region_;
    std::string service_;
    std::string scopeDate_;
    std::string expectedSignature_;
    std::vector<uint8_t> plaintext_;
    bool signatureValid_;
};


// Synchronous version for small operations
Napi::Value DecryptAndVerifySync(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsObject()) {
        Napi::TypeError::New(env, "Expected object as first argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Object params = info[0].As<Napi::Object>();
    
    try {
        // Handle masterKey as Buffer
        Napi::Buffer<uint8_t> masterKeyBuf = params.Get("masterKey").As<Napi::Buffer<uint8_t>>();
        std::string masterKey(reinterpret_cast<const char*>(masterKeyBuf.Data()), masterKeyBuf.Length());
        
        std::string salt = params.Get("salt").As<Napi::String>().Utf8Value();
        std::string info = params.Get("info").As<Napi::String>().Utf8Value();
        
        Napi::Buffer<uint8_t> ciphertextBuf = params.Get("ciphertext").As<Napi::Buffer<uint8_t>>();
        Napi::Buffer<uint8_t> tagBuf = params.Get("tag").As<Napi::Buffer<uint8_t>>();
        
        std::vector<uint8_t> ciphertext(ciphertextBuf.Data(), ciphertextBuf.Data() + ciphertextBuf.Length());
        std::vector<uint8_t> tag(tagBuf.Data(), tagBuf.Data() + tagBuf.Length());
        
        std::string stringToSign = params.Get("stringToSign").As<Napi::String>().Utf8Value();
        std::string region = params.Get("region").As<Napi::String>().Utf8Value();
        std::string service = params.Get("service").As<Napi::String>().Utf8Value();
        std::string scopeDate = params.Get("scopeDate").As<Napi::String>().Utf8Value();
        std::string expectedSignature = params.Get("expectedSignature").As<Napi::String>().Utf8Value();

        // Perform the operations synchronously
        CryptoResult result = performDecryptAndVerify(masterKey, salt, info, ciphertext, tag,
                                                     stringToSign, region, service, scopeDate, expectedSignature);
        
        if (!result.success) {
            Napi::Error::New(env, result.errorMessage).ThrowAsJavaScriptException();
            return env.Null();
        }

        Napi::Object jsResult = Napi::Object::New(env);
        jsResult.Set("signatureValid", Napi::Boolean::New(env, result.signatureValid));
        
        if (result.signatureValid) {
            jsResult.Set("secretKey", Napi::Buffer<uint8_t>::Copy(env, result.plaintext.data(), result.plaintext.size()));
        }
        
        return jsResult;
        
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        return env.Null();
    }
}

// Asynchronous version for large operations
Napi::Value DecryptAndVerifyAsync(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsObject() || !info[1].IsFunction()) {
        Napi::TypeError::New(env, "Expected (object, callback)").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Object params = info[0].As<Napi::Object>();
    Napi::Function callback = info[1].As<Napi::Function>();
    
    try {
        // Handle masterKey as Buffer
        Napi::Buffer<uint8_t> masterKeyBuf = params.Get("masterKey").As<Napi::Buffer<uint8_t>>();
        std::string masterKey(reinterpret_cast<const char*>(masterKeyBuf.Data()), masterKeyBuf.Length());
        
        std::string salt = params.Get("salt").As<Napi::String>().Utf8Value();
        std::string info = params.Get("info").As<Napi::String>().Utf8Value();
        
        Napi::Buffer<uint8_t> ciphertextBuf = params.Get("ciphertext").As<Napi::Buffer<uint8_t>>();
        Napi::Buffer<uint8_t> tagBuf = params.Get("tag").As<Napi::Buffer<uint8_t>>();
        
        std::vector<uint8_t> ciphertext(ciphertextBuf.Data(), ciphertextBuf.Data() + ciphertextBuf.Length());
        std::vector<uint8_t> tag(tagBuf.Data(), tagBuf.Data() + tagBuf.Length());
        
        std::string stringToSign = params.Get("stringToSign").As<Napi::String>().Utf8Value();
        std::string region = params.Get("region").As<Napi::String>().Utf8Value();
        std::string service = params.Get("service").As<Napi::String>().Utf8Value();
        std::string scopeDate = params.Get("scopeDate").As<Napi::String>().Utf8Value();
        std::string expectedSignature = params.Get("expectedSignature").As<Napi::String>().Utf8Value();

        VaultCryptoWorker* worker = new VaultCryptoWorker(
            callback, masterKey, salt, info, ciphertext, tag,
            stringToSign, region, service, scopeDate, expectedSignature
        );
        
        worker->Queue();
        
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
    }

    return env.Undefined();
}

// Get detailed cache statistics with hit/miss ratios
Napi::Value GetCacheStats(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    size_t hits = g_cacheHits.load();
    size_t misses = g_cacheMisses.load();
    size_t stores = g_cacheStores.load();
    size_t total = hits + misses;
    
    Napi::Object stats = Napi::Object::New(env);
    stats.Set("size", Napi::Number::New(env, g_secretKeyCache.size()));
    stats.Set("maxSize", Napi::Number::New(env, 10000));
    stats.Set("hits", Napi::Number::New(env, hits));
    stats.Set("misses", Napi::Number::New(env, misses));
    stats.Set("stores", Napi::Number::New(env, stores));
    stats.Set("total", Napi::Number::New(env, total));
    stats.Set("hitRate", Napi::Number::New(env, total > 0 ? (double)hits / total : 0.0));
    
    return stats;
}

// Clear cache manually
Napi::Value ClearCache(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    g_secretKeyCache.clear();
    
    return env.Undefined();
}

// Optimized version that accepts base64 strings directly (minimal serialization)
Napi::Value DecryptAndVerifyBase64Async(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsObject() || !info[1].IsFunction()) {
        Napi::TypeError::New(env, "Expected (object, callback)").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Object params = info[0].As<Napi::Object>();
    Napi::Function callback = info[1].As<Napi::Function>();
    
    try {
        // Handle masterKey as Buffer
        Napi::Buffer<uint8_t> masterKeyBuf = params.Get("masterKey").As<Napi::Buffer<uint8_t>>();
        std::string masterKey(reinterpret_cast<const char*>(masterKeyBuf.Data()), masterKeyBuf.Length());
        
        std::string salt = params.Get("salt").As<Napi::String>().Utf8Value();
        std::string info = params.Get("info").As<Napi::String>().Utf8Value();
        
        // Accept base64 strings directly - MUCH more efficient!
        std::string ciphertextBase64 = params.Get("ciphertextBase64").As<Napi::String>().Utf8Value();
        std::string tagBase64 = params.Get("tagBase64").As<Napi::String>().Utf8Value();
        
        // Decode in C++ (faster than JS Buffer.from)
        std::vector<uint8_t> ciphertext = decodeBase64(ciphertextBase64);
        std::vector<uint8_t> tag = decodeBase64(tagBase64);
        
        std::string stringToSign = params.Get("stringToSign").As<Napi::String>().Utf8Value();
        std::string region = params.Get("region").As<Napi::String>().Utf8Value();
        std::string service = params.Get("service").As<Napi::String>().Utf8Value();
        std::string scopeDate = params.Get("scopeDate").As<Napi::String>().Utf8Value();
        std::string expectedSignature = params.Get("expectedSignature").As<Napi::String>().Utf8Value();

        VaultCryptoWorker* worker = new VaultCryptoWorker(
            callback, masterKey, salt, info, ciphertext, tag,
            stringToSign, region, service, scopeDate, expectedSignature
        );
        
        worker->Queue();
        
    } catch (const std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
    }

    return env.Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Initialize process security settings on module load
    initializeProcessSecurity();
    
    exports.Set("decryptAndVerifySync", Napi::Function::New(env, DecryptAndVerifySync));
    exports.Set("decryptAndVerifyAsync", Napi::Function::New(env, DecryptAndVerifyAsync));
    exports.Set("decryptAndVerifyBase64Async", Napi::Function::New(env, DecryptAndVerifyBase64Async));
    exports.Set("getCacheStats", Napi::Function::New(env, GetCacheStats));
    exports.Set("clearCache", Napi::Function::New(env, ClearCache));
    return exports;
}

NODE_API_MODULE(vault_crypto_native, Init)