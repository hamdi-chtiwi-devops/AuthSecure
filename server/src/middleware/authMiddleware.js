require('dotenv').config();
const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  let token;

  // Try to get token from Authorization header
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
  }
  // If not found, try to get token from cookie
  else if (req.cookies && req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  // Handle missing token
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.', ok: false });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    // Handle invalid token
    return res.status(403).json({ message: 'Invalid token.', ok: false });
  }
};
