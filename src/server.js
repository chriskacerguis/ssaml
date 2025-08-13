require('dotenv').config();
const app = require('./app');
const { logger } = require('./utils/logger');
const port = process.env.PORT || 3000;
app.listen(port, () => logger.info(`Listening on http://localhost:${port}`));
