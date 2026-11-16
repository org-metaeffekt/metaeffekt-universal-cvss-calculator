module.exports = {
  testEnvironment: 'node',
  watchman: false,
  roots: ['<rootDir>/tests'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
};
