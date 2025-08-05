const nativeCrypto = require('./index');

function testBufferParameters() {
    if (!nativeCrypto) {
        console.log('Native crypto module not available');
        return;
    }

    console.log('Testing with Buffer parameters (like production crash)...');

    // Test parameters similar to the production crash
    const params = {
        masterKey: Buffer.from('u73YQ3S3K6iF+T2atvREEWnjTDEJKpTpFil2ulkmli/ween', 'base64'), // 128 bytes buffer
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

    console.log('Parameters:');
    console.log('- masterKey:', params.masterKey.constructor.name, '(' + params.masterKey.length + ' bytes)');
    console.log('- ciphertext:', params.ciphertext.constructor.name, '(' + params.ciphertext.length + ' bytes)');
    console.log('- tag:', params.tag.constructor.name, '(' + params.tag.length + ' bytes)');
    console.log('- Other params are strings');

    console.log('\nTesting sync version...');
    try {
        const result = nativeCrypto.decryptAndVerifySync(params);
        console.log('✅ Sync test passed! Result:', result);
    } catch (error) {
        if (error.message.includes('FATAL ERROR') || error.message.includes('napi_get_last_error_info')) {
            console.log('❌ Still crashing with N-API error:', error.message);
        } else {
            console.log('✅ Sync test passed - got expected crypto error (not a crash):', error.message);
        }
    }

    console.log('\nTesting async version...');
    nativeCrypto.decryptAndVerifyAsync(params, (error, result) => {
        if (error) {
            if (error.message && (error.message.includes('FATAL ERROR') || error.message.includes('napi_get_last_error_info'))) {
                console.log('❌ Still crashing with N-API error:', error.message);
            } else {
                console.log('✅ Async test passed - got expected crypto error (not a crash):', error.message);
            }
        } else {
            console.log('✅ Async test passed! Result:', result);
        }
        console.log('\nBuffer parameter tests completed.');
    });
}

if (require.main === module) {
    testBufferParameters();
}

module.exports = testBufferParameters;