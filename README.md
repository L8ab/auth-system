# Authentication System

A secure, production-ready authentication system with JWT tokens and password hashing.

## Features

- User registration and login
- JWT-based authentication
- Password hashing with bcrypt
- Refresh token support
- Role-based access control ready

## Tech Stack

- **Backend**: Node.js, Express.js
- **Database**: MongoDB
- **Security**: JWT, bcrypt

## Project Structure

\`\`\`
auth-system/
├── src/
│   ├── services/        # Authentication service
│   ├── models/          # User model
│   ├── middleware/      # Auth middleware
│   ├── utils/           # Password utilities
│   └── index.js         # Server entry point
├── tests/               # Test suite
└── package.json
\`\`\`

## Installation

\`\`\`bash
npm install
\`\`\`

## Usage

\`\`\`bash
npm start
\`\`\`

## API Endpoints

- \`POST /api/register\` - Register new user
- \`POST /api/login\` - User login

## Environment Variables

\`\`\`
MONGODB_URI=mongodb://localhost:27017/auth
JWT_SECRET=your-secret-key
JWT_REFRESH_SECRET=your-refresh-secret
\`\`\`

---

**POWERED BY L8AB SYSTEMS**
