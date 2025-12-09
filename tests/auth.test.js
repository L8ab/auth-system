const request = require('supertest');
const app = require('../src/index');

describe('Auth API', () => {
  test('POST /api/register should create user', async () => {
    const user = {
      name: 'Test User',
      email: 'test@example.com',
      password: 'password123'
    };
    
    const response = await request(app)
      .post('/api/register')
      .send(user)
      .expect(200);
    
    expect(response.body).toHaveProperty('user');
    expect(response.body).toHaveProperty('accessToken');
  });
  
  test('POST /api/login should authenticate user', async () => {
    const credentials = {
      email: 'test@example.com',
      password: 'password123'
    };
    
    const response = await request(app)
      .post('/api/login')
      .send(credentials)
      .expect(200);
    
    expect(response.body).toHaveProperty('accessToken');
  });
});
