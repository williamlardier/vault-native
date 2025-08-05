const nativeCrypto = require('./index');

function testCacheBehavior() {
    if (!nativeCrypto) {
        console.log('Native crypto module not available');
        return;
    }

    console.log('🧪 Testing cache behavior (not crypto correctness)...');

    // Test with completely different parameter sets to see cache isolation
    const params1 = {
        masterKey: Buffer.from('test-master-key-1-32-bytes-long!'),
        salt: 'SALT1-32-CHARACTERS-LONG-STRING!!',
        info: 'ACCESSKEY1',
        ciphertext: Buffer.from('ciphertext1data1234567890123456789012345678901234567890'),
        tag: Buffer.from('tag1234567890123'),
        stringToSign: 'STRING-TO-SIGN-1',
        region: 'us-east-1',
        service: 's3',
        scopeDate: '20250805',
        expectedSignature: 'signature1'
    };

    const params2 = {
        masterKey: Buffer.from('test-master-key-2-32-bytes-long!'),
        salt: 'SALT2-32-CHARACTERS-LONG-STRING!!', 
        info: 'ACCESSKEY2',
        ciphertext: Buffer.from('ciphertext2data1234567890123456789012345678901234567890'),
        tag: Buffer.from('tag2234567890123'),
        stringToSign: 'STRING-TO-SIGN-2',
        region: 'us-west-2',
        service: 's3',
        scopeDate: '20250806',
        expectedSignature: 'signature2'
    };

    // Clear cache and show initial state
    nativeCrypto.clearCache();
    console.log('📊 Initial cache:', nativeCrypto.getCacheStats());

    console.log('\n🔄 Testing cache miss/hit pattern...');
    
    let callCount = 0;
    const results = [];

    function makeCall(params, label, callback) {
        const start = Date.now();
        callCount++;
        
        nativeCrypto.decryptAndVerifyAsync(params, (error, result) => {
            const duration = Date.now() - start;
            const stats = nativeCrypto.getCacheStats();
            
            results.push({
                call: callCount,
                label,
                duration,
                cacheSize: stats.size,
                error: error ? error.message : null,
                success: !error
            });
            
            console.log(`   ${callCount}. ${label}: ${duration}ms, cache size: ${stats.size}, result: ${error ? 'Error' : 'Success'}`);
            
            if (callback) callback();
        });
    }

    // Test sequence
    makeCall(params1, 'Params1 - 1st call (miss)', () => {
        makeCall(params1, 'Params1 - 2nd call (hit?)', () => {
            makeCall(params2, 'Params2 - 1st call (miss)', () => {
                makeCall(params2, 'Params2 - 2nd call (hit?)', () => {
                    makeCall(params1, 'Params1 - 3rd call (hit?)', () => {
                        
                        console.log('\n📊 Final cache stats:', nativeCrypto.getCacheStats());
                        
                        console.log('\n📈 Analysis:');
                        results.forEach(r => {
                            console.log(`   ${r.call}. ${r.label}`);
                            console.log(`      Duration: ${r.duration}ms, Cache size: ${r.cacheSize}`);
                        });
                        
                        // Look for patterns
                        const param1Calls = results.filter(r => r.label.includes('Params1'));
                        const param2Calls = results.filter(r => r.label.includes('Params2'));
                        
                        console.log('\n🔍 Cache effectiveness:');
                        if (param1Calls.length >= 2) {
                            const improvement1 = ((param1Calls[0].duration - param1Calls[1].duration) / param1Calls[0].duration * 100);
                            console.log(`   Params1: ${param1Calls[0].duration}ms → ${param1Calls[1].duration}ms (${improvement1.toFixed(1)}% change)`);
                        }
                        if (param2Calls.length >= 2) {
                            const improvement2 = ((param2Calls[0].duration - param2Calls[1].duration) / param2Calls[0].duration * 100);
                            console.log(`   Params2: ${param2Calls[0].duration}ms → ${param2Calls[1].duration}ms (${improvement2.toFixed(1)}% change)`);
                        }
                        
                        console.log('\n✅ Cache behavior test completed!');
                    });
                });
            });
        });
    });
}

if (require.main === module) {
    testCacheBehavior();
}

module.exports = testCacheBehavior;