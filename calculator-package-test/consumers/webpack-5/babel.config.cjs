module.exports = {
  env: {
    production: {
      presets: [
        ['@babel/preset-env', { modules: false, targets: { esmodules: true } }],
      ],
      compact: true,
    },
  },
}
