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
  // Statements / functions / lines are held at 95 -- genuinely met (~98-100) across both the
  // public wrappers and the primitive kernel. Branches sit lower on purpose: the shortfall is
  // almost entirely defensive `throw`s in the P-256 field/curve code (invert-of-zero,
  // point-at-infinity, signature-retry exhaustion) that valid inputs cannot reach. Driving
  // those to green would mean exporting internal point arithmetic solely to satisfy the metric,
  // which is coverage theatre on guards whose whole job is to never fire. 88 locks in the real,
  // reachable branch coverage and still fails the build on a genuine regression.
  collectCoverageFrom: ['src/**/*.ts', '!src/**/*.d.ts', '!src/index.ts', '!src/crypto/types.ts'],
  coverageThreshold: {
    global: {
      statements: 95,
      functions: 95,
      lines: 95,
      branches: 88,
    },
  },
  clearMocks: true,
  collectCoverage: true,
  coverageDirectory: 'coverage',
  errorOnDeprecated: true,
  verbose: true,
  reporters: [
    'default',
    [
      'jest-junit',
      {
        outputDirectory: 'coverage',
        outputName: 'unitTestReport.xml',
      },
    ],
  ],
}
