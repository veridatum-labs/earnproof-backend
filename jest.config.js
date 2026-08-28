module.exports = {
  moduleFileExtensions: ["js", "json", "ts"],
  rootDir: ".",
  testRegex: ".*\\.spec\\.ts$",
  // The integration suite has its own config (jest.integration.config.js): it
  // needs a real PostgreSQL server, and the unit suite must stay runnable
  // without one. Ignored explicitly rather than relying on the `.int-spec.ts`
  // suffix, so a file named `*.spec.ts` under test/integration cannot quietly
  // start requiring a database here.
  testPathIgnorePatterns: ["/node_modules/", "/test/integration/"],
  transform: {
    "^.+\\.(t|j)s$": "ts-jest"
  },
  collectCoverageFrom: ["src/**/*.(t|j)s"],
  coverageDirectory: "./coverage",
  testEnvironment: "node"
};
