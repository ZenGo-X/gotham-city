#!/usr/bin/env node
"use strict";

const RSAKey = require('rsa-key');
const argv = require('yargs').argv;
const fetch = require('node-fetch');
const _ = require('lodash');
const jwkToPem = require('jwk-to-pem');

let JWT_TOKENS_AVAILABLE = false;

function waitForTokens () {
    if (!JWT_TOKENS_AVAILABLE) {
        setTimeout(waitForTokens, 1000);
    }
};

async function initJsonWebKeySet(url) {
    const response = await fetch(url);
    const jwk = await response.json();

    return  _(jwk.keys)
        .map(k => {
            const key = new RSAKey(jwkToPem(k))

            return {
                kid: k.kid,
                pem: key.exportKey(),
                der: key.exportKey('der', 'pkcs1', 'public').toString('hex'),
                alg: k.alg,
                kty: k.kty
            };
        })
        .keyBy(k => k.kid)
        .value();
}

if (!argv.region && !argv.poolid) {
    console.error('Region and poolid are required!');
    process.exit(-1);
}

const url = `https://cognito-idp.${argv.region}.amazonaws.com/${argv.poolid}/.well-known/jwks.json`;

(async () => {
    try {
        const kidTojwk = await initJsonWebKeySet(url);
        console.log(JSON.stringify(kidTojwk));
    } catch (e) {
        console.error(e);
    }

    JWT_TOKENS_AVAILABLE = true;
})();

waitForTokens();
