const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const { errorHandler } = require('./middleware/errorHandler');
const ssoRouter = require('./routes/sso');
const metaRouter = require('./routes/metadata');
const authRouter = require('./routes/auth');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
}));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.get('/', (_req, res) => res.send('IdP running.'));
app.use('/metadata', metaRouter);
app.use('/sso', ssoRouter);
app.use('/login', authRouter);
app.use(errorHandler);
module.exports = app;
