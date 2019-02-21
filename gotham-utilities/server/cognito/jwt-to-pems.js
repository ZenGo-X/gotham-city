#!/usr/bin/env node
"use strict";

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
            return {
                kid: k.kid,
                pem: jwkToPem(k)
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
console.log(`Getting jwt tokens from ${url}`);

(async () => {
    try {
        const kidTojwk = await initJsonWebKeySet(url);
        console.log(kidTojwk);
    } catch (e) {
        console.error(e);
    }

    JWT_TOKENS_AVAILABLE = true;
})();

waitForTokens();
