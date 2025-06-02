const {
  addUserService,
  getUserByEmailService,
} = require("../user/user.service");
const {
  generateToken,
  ms // Added ms
} = require("./authentication.service");
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken'); // Used by refreshTokenController

const registerController = async (req, res) => {
  try {
    const {firstName,lastName, email, password } = req.body;

    bcrypt.genSalt(13, function (err, salt) {
      bcrypt.hash(password, salt, async function (err, password) {
        try {
          const result = await addUserService({firstName,lastName, email, password });
          if (result === null) {
            res
              .status(200)
              .json({ message: "No user were registred.", ok: false });
          } else {
            res
              .status(200)
              .json({ message: "user registred successfully.", ok: true });
          }
        } catch (error) {
          return res.json({ error: error?.message ? error.message : error });
        }
      });
    });
  } catch (error) {
    return res.json({ error: error?.message ? error.message : error });
  }
};
const loginController = async (req, res) => {
  
  try {
    const { email, password } = req.body;
    const details = await  getUserByEmailService(email);
    if (!details) { // Note: getUserByEmailService now returns a single object or null.
      res.status(404).json({ message: "User not found.", ok: false });
    } else {
      // details is the user object, not an array details[0]
      bcrypt.compare(password, details.password, function (err, result) {
        if (result) {
          const token = generateToken(
            { id: details.idUser, email: details.email }, // Use details.idUser, details.email
            process.env.TOKEN_COOKIE_EXPIRES_IN || '1d'
          );
          const refreshtoken = generateToken(
            { id: details.idUser, email: details.email }, // Use details.idUser, details.email
            process.env.REFRESH_TOKEN_COOKIE_EXPIRES_IN || '7d'
          );

          res.cookie("refreshtoken", refreshtoken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: ms(process.env.REFRESH_TOKEN_COOKIE_EXPIRES_IN || '7d')
          });
          res.cookie("jwt", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: ms(process.env.TOKEN_COOKIE_EXPIRES_IN || '1d')
          });

          res.status(200).json({ // Ensure .status(200) is called before .json()
              message: "User logged successfully",
              ok: true,
              token, // Sending tokens in body is common, but primary mechanism is cookies
              refreshtoken // Same as above
            });
        } else {
          res
            .status(401) // Changed to 401 for failed login
            .json({ message: "Not credentials matching", ok: false }); // Corrected typo
        }
      });
    }
  } catch (error) {
    res.status(500).json({ error: error?.message ? error.message : error });
  }
};

const refreshTokenController = async (req, res) => {
  const { refreshtoken } = req.cookies;

  if (!refreshtoken) {
    return res.status(401).json({ message: "Refresh token not provided", ok: false });
  }

  try {
    const decoded = jwt.verify(refreshtoken, process.env.JWT_REFRESH_SECRET);
    const userPayload = { id: decoded.user.id, email: decoded.user.email }; // Correctly extracting user info
    const newAccessToken = generateToken(userPayload, process.env.TOKEN_COOKIE_EXPIRES_IN || '1d'); // Standardized expiration

    res.cookie("jwt", newAccessToken, { // Set cookie before sending response
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax', // Added sameSite
        maxAge: ms(process.env.TOKEN_COOKIE_EXPIRES_IN || '1d') // Added maxAge
    });
    res.status(200).json({ // Send response after setting cookie
        message: "Token refreshed successfully",
        ok: true,
        token: newAccessToken, // Optionally send the new token in the body as well
      });
  } catch (error) {
    return res.status(403).json({ message: "Invalid refresh token", ok: false });
  }
};

const logoutController = (req, res) => {
  res.cookie("jwt", "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax', // Added sameSite
    expires: new Date(0), // Clears cookie by setting expiry to past
  });
  res.cookie("refreshtoken", "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax', // Added sameSite
    expires: new Date(0), // Clears cookie
  });
  res.status(200).json({ message: "Logged out successfully", ok: true }); // Send response
};

module.exports = {
  registerController,
  loginController,
  refreshTokenController,
  logoutController
};
