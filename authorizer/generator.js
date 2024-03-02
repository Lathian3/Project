'use strict';

// DEPENDENCIES
const jose = require('node-jose');
const crypto = require('crypto');

// CREATE JWKS
async function jwks() {

    /*
        CREATE JWK
    */

    let key = crypto.generateKeyPairSync('rsa', {
      modulusLength: 3072,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    let cryptoKey = await jose.JWK.asKey(key.privateKey, 'pem');

    let publicKeyJSON = cryptoKey.toJSON();
    let privateKeyJSON = cryptoKey.toJSON(true);

    let time = Date.now();

    let jwksEndpoint = {
      keys: [{...publicKeyJSON,
              ...{use: "sig"},              
              ...{alg: "RS256"},
    }]};

    console.log("Public keys:");
    console.log(publicKeyJSON);

    console.log("JWKS Endpoint:");
    console.log(jwksEndpoint);

    console.log("Private keys:");
    console.log(privateKeyJSON);

    console.log("Private keys(PEM):");
    console.log(cryptoKey.toPEM(true));
}
jwks();

