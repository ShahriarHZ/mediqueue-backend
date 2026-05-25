const mysql = require('mysql2');
require('dotenv').config();

const mysql = require('mysql2');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST ? process.env.DB_HOST.trim() : '',
  user: process.env.DB_USER ? process.env.DB_USER.trim() : '',
  password: process.env.DB_PASSWORD ? process.env.DB_PASSWORD.trim() : '',
  database: process.env.DB_DATABASE ? process.env.DB_DATABASE.trim() : '',
  port: parseInt(process.env.DB_PORT) || 55637,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 15000,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000
});

module.exports = pool.promise();