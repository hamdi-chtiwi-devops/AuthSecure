require('dotenv').config();
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const {
    findUserByProviderId,
    getUserByEmailService,
    addUserService,
    linkOAuthAccount,
    // Assuming getUserByIdService exists for deserialization, though less critical for JWT
    // getUserByIdService
} = require('../user/user.service'); // Adjusted path if needed

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
    passReqToCallback: true
  },
  async (req, accessToken, refreshToken, profile, done) => {
    try {
      // console.log('Google profile:', profile); // Optional: Log profile for debugging

      const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
      const googleId = profile.id;

      // 1. Find user by googleId
      let user = await findUserByProviderId('googleId', googleId);
      if (user) {
        return done(null, user);
      }

      // 2. If no user by googleId, try to find by email (if available) and link account
      if (email) {
        const existingUserArray = await getUserByEmailService(email);
        if (existingUserArray && existingUserArray[0]) {
          const existingUser = existingUserArray[0];
          // Link Google account to existing user
          await linkOAuthAccount(existingUser.idUser, 'googleId', googleId);
          user = await findUserByProviderId('googleId', googleId); // Re-fetch user with googleId
          return done(null, user);
        }
      }

      // 3. If no user by googleId or email, create a new user
      const newUserDetails = {
        email: email,
        firstName: profile.name && profile.name.givenName ? profile.name.givenName : '',
        lastName: profile.name && profile.name.familyName ? profile.name.familyName : '',
        googleId: googleId,
        password: null // No password for OAuth users
      };

      const createdUserResult = await addUserService(newUserDetails);
      // Ensure createdUserResult and insertId are checked correctly based on your service's return
      if (createdUserResult && (createdUserResult.insertId || createdUserResult.idUser || (createdUserResult[0] && createdUserResult[0].idUser) ) ) {
         // If addUserService returns the user directly, or an array with the user
        if (createdUserResult.insertId) {
             user = await findUserByProviderId('googleId', googleId); // Fetch if only ID is returned
        } else if (Array.isArray(createdUserResult) && createdUserResult[0]) {
            user = createdUserResult[0]; // If service returns the user in an array
        }
         else {
            user = createdUserResult; // If service returns the user object directly
        }
        // If after attempting to get user, it's still not found by googleId (e.g. service returns only ID)
        if (!user || !user.googleId) {
            user = await findUserByProviderId('googleId', googleId);
        }
        return done(null, user);
      } else {
        // Log the result for more insight if user creation appears to fail
        // console.error("Failed to create or retrieve user after Google OAuth.", createdUserResult);
        return done(new Error('Failed to create new user with Google OAuth.'), null);
      }
    } catch (error) {
      // console.error("Error in Google Strategy:", error);
      return done(error, null);
    }
  }
));

// For JWT-based authentication, session management via serialize/deserialize is minimal.
// The user object from `done(null, user)` is passed to the callback route,
// which then generates a JWT.
passport.serializeUser((user, done) => {
  // user object here is what you passed to `done` in the strategy
  done(null, user.idUser); // Or user.id, depending on your user object structure
});

passport.deserializeUser(async (id, done) => {
  // This is typically used with sessions. For JWT, it's less critical
  // as user info is in the JWT. However, some setups might still use it.
  // You'd fetch the user from DB here if needed.
  // For now, just passing a minimal object.
  // const user = await getUserByIdService(id); // Example: if you have getUserByIdService
  // done(null, user);
  done(null, { idUser: id }); // Pass a representation of the user
});

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.FACEBOOK_CALLBACK_URL,
    profileFields: ['id', 'emails', 'name', 'displayName'], // Request email and name fields
    passReqToCallback: true
  },
  async (req, accessToken, refreshToken, profile, done) => {
    try {
      // console.log('Facebook profile:', profile); // Optional: Log profile for debugging

      const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
      const facebookId = profile.id;

      // 1. Find user by facebookId
      let user = await findUserByProviderId('facebookId', facebookId);
      if (user) {
        return done(null, user);
      }

      // 2. If no user by facebookId, try to find by email (if available) and link account
      if (email) {
        const existingUserArray = await getUserByEmailService(email);
        if (existingUserArray && existingUserArray[0]) {
          const existingUser = existingUserArray[0];
          // Link Facebook account to existing user
          await linkOAuthAccount(existingUser.idUser, 'facebookId', facebookId);
          user = await findUserByProviderId('facebookId', facebookId); // Re-fetch user with facebookId
          return done(null, user);
        }
      }

      // 3. If no user by facebookId or email, create a new user
      const newUserDetails = {
        email: email,
        firstName: profile.name && profile.name.givenName ? profile.name.givenName : (profile.displayName ? profile.displayName.split(' ')[0] : ''),
        lastName: profile.name && profile.name.familyName ? profile.name.familyName : (profile.displayName && profile.displayName.split(' ').length > 1 ? profile.displayName.split(' ').slice(1).join(' ') : ''),
        facebookId: facebookId,
        password: null // No password for OAuth users
      };

      const createdUserResult = await addUserService(newUserDetails);
      // Ensure createdUserResult and insertId are checked correctly based on your service's return
      if (createdUserResult && (createdUserResult.insertId || createdUserResult.idUser || (createdUserResult[0] && createdUserResult[0].idUser) ) ) {
        // If addUserService returns the user directly, or an array with the user
        if (createdUserResult.insertId) {
            user = await findUserByProviderId('facebookId', facebookId); // Fetch if only ID is returned
        } else if (Array.isArray(createdUserResult) && createdUserResult[0]) {
           user = createdUserResult[0]; // If service returns the user in an array
       } else {
           user = createdUserResult; // If service returns the user object directly
       }
       // If after attempting to get user, it's still not found by facebookId (e.g. service returns only ID)
       if (!user || !user.facebookId) {
           user = await findUserByProviderId('facebookId', facebookId);
       }
       return done(null, user);
      } else {
        // console.error("Failed to create or retrieve user after Facebook OAuth.", createdUserResult);
        return done(new Error('Failed to create new user with Facebook OAuth.'), null);
      }
    } catch (error) {
      // console.error("Error in Facebook Strategy:", error);
      return done(error, null);
    }
  }
));

// module.exports = passport; // Export if you initialize passport elsewhere by passing this module.
// Otherwise, just ensure this file is required in your main server file (e.g., index.js or app.js)
// so that passport.use() gets called.
