const nativeCrypto = require('./index');

function testCaching() {
    if (!nativeCrypto) {
        console.log('Native crypto module not available');
        return;
    }

    console.log('🧪 Testing native caching functionality...');
    console.log('Available methods:', Object.keys(nativeCrypto));

    // Test parameters (same ones used twice to test caching)
    const params = {
        masterKey: Buffer.from('test-master-key-32-bytes-long!!'),
        salt: 'FQ193UHPX76EL2HG9LEG5YE5BC4EOJ8V', 
        info: '8FR6UJ4EZNO5LTHR175O',
        ciphertext: Buffer.from([0x7e, 0x88, 0x5b, 0xa0, 0xac, 0x9e, 0xde, 0xaa, 0x0e, 0x72, 0x9d, 0xe8, 0x4d, 0x08, 0x4f, 0x85, 0x34, 0x53, 0x71, 0x10, 0xee, 0x30, 0x29, 0x2e, 0x0b, 0xbc, 0xba, 0x6d, 0x9e, 0x89, 0x25, 0x20, 0x88, 0xcb, 0x9d, 0xd4, 0x1e, 0xce, 0xbd, 0x4b]),
        tag: Buffer.from([0x82, 0x16, 0xec, 0xba, 0xb1, 0xc8, 0x13, 0xd7, 0xc7, 0x98, 0x8e, 0x33, 0x78, 0xba, 0x97, 0x40]),
        stringToSign: 'AWS4-HMAC-SHA256\n20250805T154403Z\n20250805/us-east-1/s3/aws4_request\n1f635e66e7ff830e62d842e28c42e6f4b0847eaaef16cef31584e7ce80d6aee6',
        region: 'us-east-1',
        service: 's3', 
        scopeDate: '20250805',
        expectedSignature: '44d6e43eab78b5975bb2089b5139b2f109e3e6762d71f4b77c2b82a8006d8118'
    };

    // Clear cache to start fresh
    if (nativeCrypto.clearCache) {
        nativeCrypto.clearCache();
        console.log('🧹 Cache cleared');
    }

    // Get initial cache stats
    if (nativeCrypto.getCacheStats) {
        const initialStats = nativeCrypto.getCacheStats();
        console.log('📊 Initial cache stats:', initialStats);
    }

    console.log('\n🔄 First call (should miss cache, perform decryption)...');
    const start1 = Date.now();
    
    nativeCrypto.decryptAndVerifyAsync(params, (error1, result1) => {
        const duration1 = Date.now() - start1;
        
        if (error1) {
            console.log('❌ First call failed:', error1.message);
        } else {
            console.log(`✅ First call succeeded in ${duration1}ms`);
            console.log('   Result:', result1 ? 'Success' : 'Failed');
        }

        // Get cache stats after first call
        if (nativeCrypto.getCacheStats) {
            const stats1 = nativeCrypto.getCacheStats();
            console.log('📊 Cache stats after first call:', stats1);
        }

        console.log('\n🔄 Second call (should hit cache, skip decryption)...');
        const start2 = Date.now();
        
        nativeCrypto.decryptAndVerifyAsync(params, (error2, result2) => {
            const duration2 = Date.now() - start2;
            
            if (error2) {
                console.log('❌ Second call failed:', error2.message);
            } else {
                console.log(`✅ Second call succeeded in ${duration2}ms`);
                console.log('   Result:', result2 ? 'Success' : 'Failed');
            }

            // Get final cache stats
            if (nativeCrypto.getCacheStats) {
                const stats2 = nativeCrypto.getCacheStats();
                console.log('📊 Cache stats after second call:', stats2);
            }

            // Performance comparison
            console.log('\n📈 Performance Analysis:');
            console.log(`   First call (cache miss):  ${duration1}ms`);
            console.log(`   Second call (cache hit):  ${duration2}ms`);
            
            if (duration2 < duration1) {
                const improvement = ((duration1 - duration2) / duration1 * 100).toFixed(1);
                console.log(`   🚀 Cache hit was ${improvement}% faster!`);
            } else {
                console.log('   ⚠️  No performance improvement detected');
            }

            console.log('\n🧪 Cache testing completed!');
        });
    });
}

if (require.main === module) {
    testCaching();
}

module.exports = testCaching;