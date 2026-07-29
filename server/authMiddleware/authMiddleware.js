const jwt = require('jsonwebtoken');
const User = require('../Model/User');

const requireAuth = (req, res, next) => {
  const token = req.cookies.jwt;

  if (!token) {
    console.log('No JWT token found in cookies');
    return res.redirect('/login');
  }

  jwt.verify(token, 'piuscandothis', async (err, decodedToken) => {
    if (err) {
      console.log('JWT verification failed:', err.message);
      return res.redirect('/login');
    }

    try {
      // Fetch user and attach to BOTH req and res.locals
      const user = await User.findById(decodedToken.id).select('-password'); // exclude password

      if (!user) {
        console.log('User not found for decoded token ID:', decodedToken.id);
        return res.redirect('/login');
      }

      req.user = user;           // ← CRITICAL: attach to req for controllers
      res.locals.user = user;    // ← already there for views

      console.log('Authenticated user attached:', { 
        id: user._id, 
        email: user.email 
      });

      next();

    } catch (dbErr) {
      console.error('Database error in requireAuth:', dbErr);
      return res.redirect('/login');
    }
  });
};

// checkUser remains unchanged (only for views)
const checkUser = (req, res, next) => {
  const token = req.cookies.jwt;
  if (token) {
    jwt.verify(token, 'piuscandothis', async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        const user = await User.findById(decodedToken.id).select('-password');
        res.locals.user = user || null;
        next();
      }
    });
  } else {
    res.locals.user = null;
    next();
  }
};

module.exports = { requireAuth, checkUser };