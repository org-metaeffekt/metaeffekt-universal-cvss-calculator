import type {Config} from 'jest';

const config: Config = {
  clearMocks: true,
  preset: 'ts-jest',
  testEnvironment: "jsdom",
  testMatch: [
    "**/tests/**/*.[jt]s?(x)"
  ],
  transform: {
    "^.+\\.(ts|tsx)$": [
      'ts-jest',
      {
        diagnostics: {
          ignoreCodes: [1343]
        }
      }
    ],
    '^.+\\.(js|jsx)$': 'babel-jest',
  },
  transformIgnorePatterns: [],
};

export default config;
