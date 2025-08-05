const crypto = require('crypto');
const nativeCrypto = require('./index');

function testNativeCrypto() {
    if (!nativeCrypto) {
        console.log('Native crypto module not available - skipping tests');
        return;
    }

    console.log('Testing native crypto module...');

    // Test data
    const masterKey = 'test-master-key-32-bytes-long!!';
    const salt = 'test-user-id';
    const info = 'AKIAIOSFODNN7EXAMPLE';
    const plaintext = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    
    // Mock encrypt the plaintext (normally this would be done during key creation)
    const ciphertext = Buffer.from(plaintext, 'utf8');
    const tag = crypto.randomBytes(16);

    const params = {
        masterKey,
        salt,
        info,
        ciphertext,
        tag,
        stringToSign: 'AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        region: 'us-east-1',
        service: 's3',
        scopeDate: '20130524',
        expectedSignature: 'test-signature-hex'
    };

    console.log('Testing synchronous operation...');
    try {
        const result = nativeCrypto.decryptAndVerifySync(params);
        console.log('Sync result:', result);
    } catch (error) {
        console.log('Sync test failed (expected):', error.message);
    }

    console.log('Testing asynchronous operation...');
    nativeCrypto.decryptAndVerifyAsync(params, (error, result) => {
        if (error) {
            console.log('Async test failed (expected):', error.message);
        } else {
            console.log('Async result:', result);
        }
        console.log('Native crypto tests completed.');
    });
}

if (require.main === module) {
    testNativeCrypto();
}

module.exports = testNativeCrypto;