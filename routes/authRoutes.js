import express from 'express';
import { register, login, logout } from '../controllers/authController.js';
import rateLimit from 'express-rate-limit';

const router = express.Router();

// Rate limiting to protect against brute force attacks
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per `window`
  message: 'Too many login attempts from this IP, please try again after 15 minutes',
});

// Render login and signup pages with CSRF token
router.get('/login', (req, res) => res.render('login', { csrfToken: req.csrfToken() }));
router.get('/signup', (req, res) => res.render('signup', { csrfToken: req.csrfToken(), errorMessage: null }));

router.post('/register', register);
router.post('/login', loginLimiter, login);
router.get('/logout', logout);

export default router;
