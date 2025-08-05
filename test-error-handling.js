const nativeCrypto = require('./index');

function testErrorHandling() {
    if (!nativeCrypto) {
        console.log('Native crypto module not available - skipping error handling tests');
        return;
    }

    console.log('Testing error handling in native crypto module...');

    // Test cases for parameter validation
    const testCases = [
        {
            name: 'Missing masterKey',
            params: {
                salt: 'test-salt',
                info: 'test-info',
                ciphertext: Buffer.from('test'),
                tag: Buffer.from('testtag12345678'),
                stringToSign: 'test-string',
                region: 'us-east-1',
                service: 's3',
                scopeDate: '20130524',
                expectedSignature: 'test-sig'
            }
        },
        {
            name: 'masterKey is null',
            params: {
                masterKey: null,
                salt: 'test-salt',
                info: 'test-info',
                ciphertext: Buffer.from('test'),
                tag: Buffer.from('testtag12345678'),
                stringToSign: 'test-string',
                region: 'us-east-1',
                service: 's3',
                scopeDate: '20130524',
                expectedSignature: 'test-sig'
            }
        },
        {
            name: 'masterKey is not a string',
            params: {
                masterKey: 12345,
                salt: 'test-salt',
                info: 'test-info',
                ciphertext: Buffer.from('test'),
                tag: Buffer.from('testtag12345678'),
                stringToSign: 'test-string',
                region: 'us-east-1',
                service: 's3',
                scopeDate: '20130524',
                expectedSignature: 'test-sig'
            }
        },
        {
            name: 'ciphertext is not a buffer',
            params: {
                masterKey: 'test-key',
                salt: 'test-salt',
                info: 'test-info',
                ciphertext: 'not-a-buffer',
                tag: Buffer.from('testtag12345678'),
                stringToSign: 'test-string',
                region: 'us-east-1',
                service: 's3',
                scopeDate: '20130524',
                expectedSignature: 'test-sig'
            }
        },
        {
            name: 'tag is missing',
            params: {
                masterKey: 'test-key',
                salt: 'test-salt',
                info: 'test-info',
                ciphertext: Buffer.from('test'),
                stringToSign: 'test-string',
                region: 'us-east-1',
                service: 's3',
                scopeDate: '20130524',
                expectedSignature: 'test-sig'
            }
        },
        {
            name: 'Valid parameters (should work but might fail crypto validation)',
            params: {
                masterKey: 'test-master-key-32-bytes-long!!',
                salt: 'test-salt',
                info: 'test-info',
                ciphertext: Buffer.from('test-ciphertext'),
                tag: Buffer.from('testtag123456789'),
                stringToSign: 'test-string-to-sign',
                region: 'us-east-1',
                service: 's3',
                scopeDate: '20130524',
                expectedSignature: 'test-signature'
            }
        }
    ];

    testCases.forEach(testCase => {
        console.log(`\nTesting: ${testCase.name}`);
        
        try {
            const result = nativeCrypto.decryptAndVerifySync(testCase.params);
            console.log(`  ✓ Success: ${JSON.stringify(result)}`);
        } catch (error) {
            console.log(`  ✗ Error (may be expected): ${error.message}`);
        }
    });

    console.log('\nTesting async version with invalid parameters...');
    
    // Test async version with missing parameter
    try {
        nativeCrypto.decryptAndVerifyAsync({
            salt: 'test-salt'
            // masterKey missing
        }, (error, result) => {
            if (error) {
                console.log('  ✗ Async error (expected):', error.message);
            } else {
                console.log('  ✓ Async success:', result);
            }
        });
    } catch (error) {
        console.log('  ✗ Async sync error (expected):', error.message);
    }

    console.log('\nError handling tests completed.');
}

if (require.main === module) {
    testErrorHandling();
}

module.exports = testErrorHandling;