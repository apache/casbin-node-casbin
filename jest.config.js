module.exports = {
  testEnvironment: 'node',
  transform: {
    '^.+\\.(ts|tsx)$': 'ts-jest',
  },
  moduleNameMapper: {
    'csv-parse': '<rootDir>/node_modules/csv-parse/dist/cjs/sync.cjs',
  },
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json'],
  coverageReporters: ['lcov', 'text'],
  collectCoverageFrom: ['src/**/*.ts'],
};
