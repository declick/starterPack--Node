import express from 'express';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import csrf from 'csurf';
import { expressjwt as jwt } from 'express-jwt';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import jsonwebtoken from 'jsonwebtoken';
import authRoutes from './routes/authRoutes.js';
import userRoutes from './routes/userRoutes.js';
import homeRoutes from './routes/homeRoutes.js';
import config from './config/config.js';

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

mongoose.connect(config.mongodbUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('Connected to MongoDB');
}).catch((err) => {
  console.error('MongoDB connection error:', err);
});

const csrfProtection = csrf({ cookie: true });

app.use(cors({
  credentials: true,
}));

app.use(express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(csrfProtection);

// Middleware to pass authenticated user to views
app.use((req, res, next) => {
  const token = req.cookies.token;
  if (token) {
    jsonwebtoken.verify(token, config.jwtSecret, (err, decoded) => {
      if (err) {
        res.locals.user = null;
      } else {
        res.locals.user = decoded;
      }
      next();
    });
  } else {
    res.locals.user = null;
    next();
  }
});

// Routes
app.use('/', homeRoutes);
app.use('/', authRoutes);
app.use('/', userRoutes);

// Middleware pour gérer les erreurs d'authentification et rediriger les utilisateurs non autorisés
app.use((err, req, res, next) => {
  if (err.name === 'UnauthorizedError') {
    return res.redirect('/');
  }
  next(err);
});

const PORT = config.port;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
