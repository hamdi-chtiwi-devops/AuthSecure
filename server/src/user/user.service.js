const db = require("../../database-mysql/index");

// Modified addUserService to support OAuth fields and return useful data
const addUserService = async (userData) => {
  return new Promise(async (resolve, reject) => {
    const {
      firstName = null,
      lastName = null, // Corrected: was lastNAme
      email = null,
      password = null, // Will be null for OAuth users
      googleId = null,
      facebookId = null
    } = userData;

    // Basic validation for email (can be adjusted based on requirements)
    // if (!email && !googleId && !facebookId) { // Or some other logic
    //   return reject(new Error("Email or provider ID is required to create a user."));
    // }

    const query = "INSERT INTO user (firstName, lastName, email, password, googleId, facebookId) VALUES (?, ?, ?, ?, ?, ?)";
    const values = [firstName, lastName, email, password, googleId, facebookId];

    db.query(query, values, (error, results) => {
      if (error) {
        if (error.code === 'ER_DUP_ENTRY') {
          // More specific error message could be useful, e.g., based on which field caused the duplication
          return reject(new Error("User with this email or provider ID already exists."));
        }
        return reject(error);
      }
      if (results.affectedRows === 0) {
        resolve(null); // Or reject(new Error("User creation failed, no rows affected."))
      } else {
        // Return the insertId and other relevant info, including the original userData
        // This helps Passport strategy to get the full user object or enough info to retrieve it
        resolve({ insertId: results.insertId, ...userData });
      }
    });
  });
};

// New function: findUserByProviderId
const findUserByProviderId = async (providerField, providerId) => {
  return new Promise(async (resolve, reject) => {
    if (!['googleId', 'facebookId'].includes(providerField)) {
      return reject(new Error("Invalid provider field specified."));
    }
    const query = `SELECT * FROM user WHERE ${providerField} = ?`;
    db.query(query, [providerId], (error, results) => {
      if (error) {
        return reject(error);
      }
      if (results.length === 0) {
        resolve(null);
      } else {
        resolve(results[0]); // Return single user object
      }
    });
  });
};

// New function: linkOAuthAccount
const linkOAuthAccount = async (userId, providerField, providerId) => {
  return new Promise(async (resolve, reject) => {
    if (!['googleId', 'facebookId'].includes(providerField)) {
      return reject(new Error("Invalid provider field specified for linking."));
    }
    if (!userId || !providerId) {
        return reject(new Error("User ID and Provider ID are required for linking."));
    }
    const query = `UPDATE user SET ${providerField} = ? WHERE idUser = ?`;
    db.query(query, [providerId, userId], (error, results) => {
      if (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return reject(new Error(`This ${providerField.replace('Id','')} account is already linked to another user.`));
        }
        return reject(error);
      }
      // changedRows indicates if the update actually changed a row.
      // If 0, it might mean the value was already set, or idUser not found.
      // For simplicity, we can resolve, but in a real app, might check if idUser exists first.
      resolve(results); // Resolve with results, caller can check changedRows
    });
  });
};

// Preserved updateUserService (no changes from original)
const updateUserService = async (idUser,fieldsToUpdate) => {
  return new Promise(async (resolve, reject) => {
    const query = "UPDATE user SET ? WHERE idUser = ?";
    db.query(query, [fieldsToUpdate, idUser], (error, results) => {
      if (error) {
        reject(error);
      } else {
        if (results.changedRows === 0) {
          resolve(null);
        } else {
          resolve(results);
        }
      }
    });
  });
};

// Preserved getUserByIdService (no changes from original, though it returns [results])
// Note: Passport's deserializeUser might expect a single object. If this is used for that,
// it might need adjustment similar to getUserByEmailService. For now, keeping as is.
const getUserByIdService = async (id) => {
  return new Promise(async (resolve, reject) => {
    const query = "SELECT * FROM user WHERE idUser = ?";
    db.query(query, [id], (error, results) => {
      if (error) {
        reject(error);
      } else {
        if (results.length === 0) {
          resolve(null);
        } else {
          resolve([results]); // Original returns an array within an array for a single user
        }
      }
    });
  });
};

// Modified getUserByEmailService to return a single user object or null
const getUserByEmailService = async (email) => {
  return new Promise(async (resolve, reject) => {
    const query = "SELECT * FROM user WHERE email = ?";
    db.query(query, [email], (error, results) => {
      if (error) {
        return reject(error);
      }
      if (results.length === 0) {
        resolve(null);
      } else {
        resolve(results[0]); // Return the first user found (single object)
      }
    });
  });
};

// Preserved getAllUserService (no changes from original)
const getAllUserService = async () => {
  return new Promise(async (resolve, reject) => {
    const query = "SELECT * FROM user";
    db.query(query, (error, results) => {
      if (error) {
        reject(error);
      } else {
        if (results.length === 0) {
          resolve(null);
        } else {
          resolve([results]);
        }
      }
    });
  });
};

// Preserved deleteUserByIdService (no changes from original)
const deleteUserByIdService = async (id) => {
  return new Promise(async (resolve, reject) => {
    const query = "UPDATE user SET deactivated = 1 WHERE idUser = ?";
    db.query(query, [id], (error, result) => {
      if (error) {
        reject(error);
      } else {
        if (result.changedRows === 0) {
          resolve(null);
        } else {
          resolve(result);
        }
      }
    });
  });
};

module.exports = {
  addUserService,
  updateUserService,
  getUserByIdService,
  getAllUserService,
  deleteUserByIdService,
  getUserByEmailService,
  findUserByProviderId, // Added
  linkOAuthAccount    // Added
};
