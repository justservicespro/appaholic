// Vercel zero-config Node builder auto-detects any file under /api as a
// serverless function. This file simply re-exports the Express app defined
// in ../index.js so all routes (/api/*, /auth/*, etc.) are served correctly
// once deployed. Do not put route logic here — it belongs in ../index.js.
module.exports = require('../index.js');
