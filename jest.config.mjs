// jest.config.mjs
export default {
  transform: {
    '^.+\\.ts$': 'babel-jest',
  },
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  transformIgnorePatterns: [
    '/node_modules/(?!(your-package-name)/)',
  ],
  testEnvironment: 'node',
};
