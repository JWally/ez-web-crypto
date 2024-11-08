// jest.config.mjs
export default {
  transform: {
    '^.+\\.ts$': 'babel-jest',
  },
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  transformIgnorePatterns: ['/node_modules/(?!(your-package-name)/)'],
  testEnvironment: 'node',
  "coverageThreshold": {
    "global": {
      "branches": 80,
      "functions": 80,
      "statements": 80
    }
  },
  "clearMocks": true,
  "collectCoverage": true,
  "coverageDirectory": "coverage",
  "errorOnDeprecated": true,
  "verbose": true,
  "reporters": [
    "default",
    [
      "jest-junit",
      {
        "outputDirectory": "coverage",
        "outputName": "unitTestReport.xml"
      }
    ]
  ]
}
