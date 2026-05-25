const mysql = require('mysql2');
require('dotenv').config();

// Create a connection pool instead of a single connection
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,       // Max simultaneous tunnels Vercel can open
  queueLimit: 0,
  connectTimeout: 15000,     // Gives the cloud network 15 seconds to handshake
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000
});

// Export the promise-based pool interface
module.exports = pool.promise();