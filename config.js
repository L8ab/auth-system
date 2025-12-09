// Example configuration file
module.exports = {
  port: process.env.PORT || 3000,
  database: {
    uri: process.env.DATABASE_URI || 'mongodb://localhost:27017/app',
    options: {
      useNewUrlParser: true,
      useUnifiedTopology: true
    }
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'your-secret-key',
    expiresIn: '15m'
  },
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379'
  }
};

