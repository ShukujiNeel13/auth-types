// TODO: convert pm.variables.get to collectionVariables lookup
// const collectionVariables = pm.variables.toObject();

if (pm.variables.has('auth-type') == false) {
    throw new Error('"auth-type" not found in Variables (Required)');
}
const authType = pm.variables.get('auth-type');
// console.log(`authType in variables is: ${authType}`);

const headerNameAuth = 'Authorization';

if (authType == 'basic') {
    // Create basic signature

    if (pm.variables.has('sc-username') == false) {
        console.error('"sc-username" not found in Variables (Required for auth-type: basic)')
        throw '"sc-username" not found in Variables (Required for auth-type: basic)';
    }

    if (pm.variables.has('sc-password') == false) {
        console.error();
        throw '"sc-password" not found in Variables (Required for auth-type: basic)';
    }

    const username = pm.variables.get('sc-username');
    const password = pm.variables.get('sc-password');

    const combinedCredentials = `${username}:${password}`;
    const base64EncodedCombinedCredentials = new Buffer(combinedCredentials).toString('base64');

    const headerValueAuth = `Basic ${base64EncodedCombinedCredentials}`;

    // console.log(`HEADER value for ${authType} auth created as\n${headerValueAuth}`);

    pm.request.headers.add({
        'key': headerNameAuth,
        'value': headerValueAuth
    });

}
else if (authType == 'hmac') {

    // Reference for SC-HMAC signing: https://www.apidocs.smartclean.io/hmac.html

    if (pm.variables.has('sc-hmac-access-key') == false) {
        throw new Error('"sc-hmac-access-key" not found in Variables (Required for auth-type: hmac)');
    }
    if (pm.variables.has('sc-hmac-secret-key') == false) {
        throw new Error('"sc-hmac-secret-key" not found in Variables (Required for auth-type: hmac)');
    }
    if (pm.variables.has('sc-hmac-prefix') == false) {
        throw new Error('"sc-hmac-prefix" not found in Variables (Required for auth-type: hmac)');
    }

    let currentUnixTimeSeconds = Math.floor(Date.now() / 1000);

    if (pm.variables.has('header-name-sc-time')) {
        const headerNameXScTime = pm.variables.get('header-name-sc-time')
        pm.request.headers.add({
            'key': headerNameXScTime,
            'value': currentUnixTimeSeconds
        });
    }

    if (pm.variables.has('header-name-sc-identity')) {
        const headerNameXScIdentity = pm.variables.get('header-name-sc-identity');

        if (pm.variables.has('header-value-sc-identity') == false) {
            throw new Error('"sc-header-value-x-sc-identity" not found in Variables (Required as sc-header-name-sc-identity-is found in variables.)');
            }

        const headerValueXScIdentity = pm.variables.get('header-value-sc-identity');

        pm.request.headers.add({
            'key': headerNameXScIdentity,
            'value': headerValueXScIdentity
        });
    }
    
    // console.log('Request URL is:')
    // console.log(pm.request.url);

    const scModule = pm.request.url.path[0]
    // console.log('Module from URL path is:')
    // console.log(scModule);

    const requestQueryOp = pm.request.url.query.get('op')
    // console.log('"op" from URL queryparams is:')
    // console.log(requestQueryOp);
    
    const accessKey = pm.variables.get('sc-hmac-access-key');
    // console.log(`access key is: ${accessKey}`);

    const propId = pm.variables.get('propid');

    const stringToSign = `${scModule}/${propId}/${requestQueryOp}/${accessKey}/${currentUnixTimeSeconds}`;

    console.log('String to Sign created as:');
    // console.log(stringToSign);

    const secretKey = pm.variables.get('sc-hmac-secret-key');
    console.log(`secret key is: ${secretKey}`);

    const scHmacPrefix = pm.variables.get('sc-hmac-prefix');
    // console.log(`sc-hmac-prefix is: ${scHmacPrefix}`);

    const hmacSignature = CryptoJS.enc.Hex.stringify(CryptoJS.HmacSHA256(stringToSign, secretKey));

    const headerValueAuth = `${scHmacPrefix};${accessKey};${hmacSignature}`;

    // console.log(`HEADER value for ${authType} auth created as\n${authHeaderValue}`);

    pm.request.headers.add({
        'key': headerNameAuth,
        'value': headerValueAuth
    });
} 
else {
    throw new Error(`Variable "auth-type" ${authType} is invalid (Valid types: "basic" or "hmac")`);
}
