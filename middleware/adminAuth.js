
const requireRole = require('./roleAuth');

// Both the original administrator and database
// administrators receive the same permissions.
const requireAdmin = requireRole('admin');

module.exports = requireAdmin;
