const express = require('express');
const createError = require('http-errors');
const morgan = require('morgan');
require('dotenv').config();
const JWT = require('jsonwebtoken');
const { generateKeyPairSync } = require('node:crypto');
const FILE = require('fs');
const jose = require('node-jose');


const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(morgan('dev'));


app.post('/auth:expired?', async (req, res, next) => {
  
  var private = FILE.readFileSync('./certs/private.json')
  private = JSON.parse(private);
  console.log(private.kid);
  if(req.params.expired === "true"){
    const opt = { compact: true, jwk: private, fields: { typ: "jwt" } };

    const payload = JSON.stringify({
      exp: Math.floor(Date.now() / 1000),
      iat: Math.floor(Date.now() / 1000),
      sub: "test",
    });
  
    const token = await jose.JWS.createSign(opt, private).update(payload).final();
    
    res.status(200).send({ token });
  }else{
    const opt = { compact: true, jwk: private, fields: { typ: "jwt" } };

    const payload = JSON.stringify({
      exp: Math.floor(Date.now() / 1000),
      iat: Math.floor(Date.now() / 1000),
      sub: "test",
    });
  
    const token = await jose.JWS.createSign(opt, private).update(payload).final();
  
    res.status(200).send({ token });
  }
});

app.get('/auth', async (req,res, next) => {
  res.status(404).send("No Content");
});

app.put('/auth', async (req,res, next) => {
  res.status(404).send("No Content");
});

app.delete('/auth', async (req,res, next) => {
  res.status(404).send("No Content");
});

app.patch('/auth', async (req,res, next) => {
  res.status(404);
});

app.head('/auth', async (req,res, next) => {
  res.status(204);
});

app.post('/.well-known/jwks.json', async (req, res, next) => {
  res.status(404).send("No Content");
});

app.put('/.well-known/jwks.json', async (req, res, next) => {
  res.status(404).send("No Content");
});

app.delete('/.well-known/jwks.json', async (req, res, next) => {
  res.status(404).send("No Content");
});

app.patch('/.well-known/jwks.json', async (req, res, next) => {
  res.status(204).send("No Content");
});


app.get('/.well-known/jwks.json', async (req, res, next) => {
  var public = FILE.readFileSync('./.well-known/jwks.json')
  public = JSON.parse(public);
  res.send({ public });
});


app.use('/api', require('./routes/api.route'));

app.use((req, res, next) => {
  next(createError.NotFound());
});

app.use((err, req, res, next) => {
  res.status(err.status || 500);
  res.send({
    status: err.status || 500,
    message: err.message,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 @ http://localhost:${PORT}`));
