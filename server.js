const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3');

const app = express();
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;

let db = new sqlite3.Database('totally_not_my_privateKeys.db');

async function createTable(db) {db.exec('CREATE TABLE IF NOT EXISTS keys ( kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL);');
}

async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
}

async function insertKeys(db) {

  //const sqlQuery = `INSERT INTO keys (key, exp) VALUES ( '` + keyPair.toPEM() + `', ` + `${Math.floor(Date.now() / 1000) + 3600}` + `), ( '` + expiredKeyPair.toPEM() + `' , ` + `${Math.floor(Date.now() / 1000) - 3600}` + `);`
  
  let sqlQuery = 'INSERT INTO keys (key, exp) VALUES(:key, :exp);';
  
  db.run(sqlQuery, [keyPair.toPEM(), Math.floor(Date.now() / 1000) + 3600]);
  db.run(sqlQuery, [expiredKeyPair.toPEM(),Math.floor(Date.now() / 1000) - 3600]);
}

function generateToken() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: keyPair.kid
    }
  };

  token = jwt.sign(payload, keyPair.toPEM(true), options);
}

function generateExpiredJWT() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: expiredKeyPair.kid
    }
  };

  expiredToken = jwt.sign(payload, expiredKeyPair.toPEM(true), options);
}

app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.get('/.well-known/jwks.json', (req, res) => {
  const validKeys = [keyPair].filter(key => !key.expired);
  res.setHeader('Content-Type', 'application/json');
  res.json({ keys: validKeys.map(key => key.toJSON()) });
});

app.post('/auth', (req, res) => {

  if (req.query.expired === 'true'){
    return res.send(expiredToken);
  }
  res.send(token);
});

generateKeyPairs().then(() => {
  createTable(db);
  insertKeys(db);
  generateToken()
  generateExpiredJWT()
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});
