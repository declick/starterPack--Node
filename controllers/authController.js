import User from '../models/User.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import config from '../config/config.js';

export const register = async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.redirect('/login');
  } catch (error) {
    if (error.code === 11000) {
      res.render('signup', { csrfToken: req.csrfToken(), errorMessage: 'Username already exists. Please choose another username.' });
    } else {
      console.error('Registration error:', error);
      res.status(500).send('Registration failed: ' + error.message);
    }
  }
};

export const login = async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).send('Authentication failed');
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).send('Authentication failed');
    }
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      config.jwtSecret,
      { expiresIn: '7d' } 
    );
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 60 * 60 * 1000 }); // Le cookie expire en 7 jours
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send('Login failed: ' + error.message);
  }
};

export const logout = (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
};
