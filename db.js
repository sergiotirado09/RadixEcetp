'use strict';

require('dotenv').config();

const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Falta configurar la variable de entorno ${name}.`);
  }
  return value;
}

function createDatabasePool() {
  const caBase64 = process.env.DB_SSL_CA_BASE64;
  const caPath = path.join(__dirname, 'ca.pem');
  const ca = caBase64
    ? Buffer.from(caBase64, 'base64').toString('utf8')
    : fs.existsSync(caPath)
      ? fs.readFileSync(caPath, 'utf8')
      : undefined;
  const port = Number(required('DB_PORT'));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('DB_PORT debe ser un puerto válido entre 1 y 65535.');
  }
  const ssl = ca ? { ca, rejectUnauthorized: true } : { rejectUnauthorized: true };

  return mysql.createPool({
    host: required('DB_HOST'),
    port,
    database: required('DB_NAME'),
    user: required('DB_USER'),
    password: required('DB_PASSWORD'),
    ssl,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    charset: 'utf8mb4'
  });
}

module.exports = { createDatabasePool };
