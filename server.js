const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3');
const crypto = require('crypto');
const { uuid } = require('uuidv4');
const argon2 = require('argon2');
const requestIP = require('request-ip');

const app = express();
app.use(express.json());

const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;
let username;
let email;

let db = new sqlite3.Database('totally_not_my_privateKeys.db');

async function createKeysTable(db) {db.exec('CREATE TABLE IF NOT EXISTS keys ( kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL);');
}

async function createUsersTable(db) {db.exec('CREATE TABLE IF NOT EXISTS users ( id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_login TIMESTAMP );');
}

async function createAuthLogTable(db) {db.exec('CREATE TABLE IF NOT EXISTS auth_logs ( id INTEGER PRIMARY KEY AUTOINCREMENT, request_ip TEXT NOT NULL, request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, user_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id));');
}

async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
}

async function insertKeys(db) {

  //const sqlQuery = `INSERT INTO keys (key, exp) VALUES ( '` + keyPair.toPEM() + `', ` + `${Math.floor(Date.now() / 1000) + 3600}` + `), ( '` + expiredKeyPair.toPEM() + `' , ` + `${Math.floor(Date.now() / 1000) - 3600}` + `);`
  
  let iv = '1234567891123456'

  let sqlQuery = 'INSERT INTO keys (key, exp) VALUES(:key, :exp);';

  const AESkey = process.env.NOT_MY_KEY;
  const algorithm = 'aes-256-cbc';
  const cipher = crypto.createCipheriv(algorithm, AESkey, iv);
  const encrytedKey = cipher.update(keyPair.toPEM(true));
  const expiredEncrytedKey = cipher.update(expiredKeyPair.toPEM(true));

  db.run(sqlQuery, [encrytedKey, Math.floor(Date.now() / 1000) + 3600]);
  db.run(sqlQuery, [expiredEncrytedKey,Math.floor(Date.now() / 1000) - 3600]);
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

app.all('/register', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
})

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

  db.get(`SELECT * FROM users WHERE username="${username}"`, (error, row) => { 
    let userID = row.id;
    let address = requestIP.getClientIp(req);
    db.run(`INSERT INTO auth_logs (request_ip, user_id) VALUES("${address}", ${userID});`);
  });

  if (req.query.expired === 'true'){
    return res.send(expiredToken);
  }
  res.send(token);
});

app.post('/register', (req, res) => {
  
  username = req.body.username;
  email = req.body.email;
  let uuidv4Password = uuid();
  argon2.hash(uuidv4Password).then(hash => {
    let sqlQuery = 'INSERT INTO users (username, password_hash, email) VALUES(:username, "';
    sqlQuery += hash;
    sqlQuery += '", :email);';
    db.run(sqlQuery, [username, email]);

    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({ password: uuidv4Password });
  })
})

generateKeyPairs().then(() => {
  createKeysTable(db);
  createUsersTable(db);
  createAuthLogTable(db);
  insertKeys(db);
  generateToken()
  generateExpiredJWT()
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});
