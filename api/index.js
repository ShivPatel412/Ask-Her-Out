// Vercel serverless function wrapper for the Express app
const { app } = require('../server.js');

module.exports = (req, res) => app(req, res);
