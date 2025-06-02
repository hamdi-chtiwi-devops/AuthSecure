const jwt = require("jsonwebtoken");

const generateToken = (user, expiresIn) => {
    // Ensure user is correctly passed in the payload structure expected by your JWT consumers
    // e.g., if your JWT middleware expects `id` directly in payload, use jwt.sign(user, ...)
    // If it expects `{ user: { id: ..., email: ... } }`, then jwt.sign({ user }, ...) is correct.
    // Based on refreshTokenController, it seems { user: { id: ..., email: ... } } is the structure.
    const token = jwt.sign({ user }, process.env.JWT_SECRET, { expiresIn });
    return token;
};

const ms = (str) => {
  if (!str) return undefined;
  // If already a number, assume it's milliseconds
  if (typeof str === 'number') return str;

  const match = str.match(/^(\d+)([smhd])$/);
  if (!match) {
    // Try to parse as a number if no unit, assuming it's milliseconds
    const num = Number(str);
    return isNaN(num) ? undefined : num;
  }
  const val = parseInt(match[1]);
  const unit = match[2];
  if (unit === 's') return val * 1000;
  if (unit === 'm') return val * 60 * 1000;
  if (unit === 'h') return val * 60 * 60 * 1000;
  if (unit === 'd') return val * 24 * 60 * 60 * 1000;
  return undefined;
};

module.exports = { generateToken, ms };