const nativeCrypto = require('./index');

function testExactProductionParams() {
    if (!nativeCrypto) {
        console.log('Native crypto module not available');
        return;
    }

    console.log('Testing with EXACT production crash parameters...');

    // These are the exact parameters from the production crash
    const params = {
        masterKey: Buffer.from('75373359515335344b3669462b54326174765245455769545445454a4b7054754669613275626b6d6c692f7765656e52355947', 'hex'), // reconstructed from the hex shown
        salt: 'FQ193UHPX76EL2HG9LEG5YE5BC4EOJ8V',
        info: '8FR6UJ4EZNO5LTHR175O',
        ciphertext: Buffer.from([0x7e, 0x88, 0x5b, 0xa0, 0xac, 0x9e, 0xde, 0xaa, 0x0e, 0x72, 0x9d, 0xe8, 0x4d, 0x08, 0x4f, 0x85, 0x34, 0x53, 0x71, 0x10, 0xee, 0x30, 0x29, 0x2e, 0x0b, 0xbc, 0xba, 0x6d, 0x9e, 0x89, 0x25, 0x20, 0x88, 0xcb, 0x9d, 0xd4, 0x1e, 0xce, 0xbd, 0x4b]),
        tag: Buffer.from([0x82, 0x16, 0xec, 0xba, 0xb1, 0xc8, 0x13, 0xd7, 0xc7, 0x98, 0x8e, 0x33, 0x78, 0xba, 0x97, 0x40]),
        stringToSign: 'AWS4-HMAC-SHA256\n20250805T154957Z\n20250805/us-east-1/s3/aws4_request\n10f8ec68acaee54a82c2fd22e1196e5baf2c23cdfe554b5a5e5544cae373b2bb',
        region: 'us-east-1',
        service: 's3',
        scopeDate: '20250805',
        expectedSignature: 'd5675ee8444ec6b042b99e4f87fc7a919d9d69054f5b9e6742b6c2f3b98121e4'
    };

    console.log('Validating parameter types:');
    Object.keys(params).forEach(key => {
        const value = params[key];
        const type = Buffer.isBuffer(value) ? 'Buffer' : typeof value;
        const length = Buffer.isBuffer(value) ? `${value.length} bytes` : `${value.length} chars`;
        console.log(`- ${key}: ${type} (${length})`);
        
        if (value === null) console.log(`  ⚠️  ${key} is NULL!`);
        if (value === undefined) console.log(`  ⚠️  ${key} is UNDEFINED!`);
    });

    console.log('\n=== Testing sync version ===');
    try {
        const result = nativeCrypto.decryptAndVerifySync(params);
        console.log('✅ SUCCESS: No crash, got result:', result);
    } catch (error) {
        if (error.message && (error.message.includes('FATAL ERROR') || error.message.includes('napi_get_last_error_info'))) {
            console.log('❌ CRASH: Still getting N-API error:', error.message);
            console.log('This means our fix is incomplete!');
        } else {
            console.log('✅ SUCCESS: No crash, got expected error:', error.message);
        }
    }

    console.log('\n=== Testing async version ===');
    try {
        nativeCrypto.decryptAndVerifyAsync(params, (error, result) => {
            if (error) {
                if (error.message && (error.message.includes('FATAL ERROR') || error.message.includes('napi_get_last_error_info'))) {
                    console.log('❌ CRASH: Still getting N-API error:', error.message);
                    console.log('This means our fix is incomplete!');
                } else {
                    console.log('✅ SUCCESS: No crash, got expected error:', error.message);
                }
            } else {
                console.log('✅ SUCCESS: No crash, got result:', result);
            }
        });
    } catch (syncError) {
        if (syncError.message && (syncError.message.includes('FATAL ERROR') || syncError.message.includes('napi_get_last_error_info'))) {
            console.log('❌ CRASH: Still getting N-API error in async setup:', syncError.message);
            console.log('This means our fix is incomplete!');
        } else {
            console.log('Got sync error in async setup:', syncError.message);
        }
    }
}

if (require.main === module) {
    testExactProductionParams();
}

module.exports = testExactProductionParams;