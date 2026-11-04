const express = require('express');
const router = express.Router();
const {
  register,
  login,
  adminLogin,
  googleAuth,
} = require('../controllers/authController');

router.post('/register', register);
router.post('/login', login);
router.post('/admin-login', adminLogin);
router.post('/google', googleAuth);

module.exports = router;