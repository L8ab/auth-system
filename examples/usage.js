// Authentication System Usage Example

const authService = require('../src/services/authService');

// Register a new user
async function registerUser() {
  try {
    const result = await authService.register({
      name: 'John Doe',
      email: 'john@example.com',
      password: 'securepassword123'
    });
    console.log('User registered:', result.user);
    console.log('Access Token:', result.accessToken);
  } catch (error) {
    console.error('Registration failed:', error.message);
  }
}

// Login user
async function loginUser() {
  try {
    const result = await authService.login('john@example.com', 'securepassword123');
    console.log('Login successful:', result.user);
    console.log('Access Token:', result.accessToken);
  } catch (error) {
    console.error('Login failed:', error.message);
  }
}

// Run examples
// registerUser();
// loginUser();
