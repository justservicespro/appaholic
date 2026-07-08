// Vercel's zero-config Node builder auto-detects any file under /api as a
// serverless function. This re-exports the Express app from ../index.js.
module.exports = require('../index.js');
