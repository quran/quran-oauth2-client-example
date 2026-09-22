const { defineConfig } = require('@playwright/test');
require('dotenv').config();

module.exports = defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  use: {
    baseURL: process.env.BASE_PATH || 'http://localhost:3005',
    screenshot: 'off',
    trace: 'off',
    video: 'off',
  },
});
