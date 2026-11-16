const path = require('path')
const { VueLoaderPlugin } = require('vue-loader')

const outputPath = path.resolve(__dirname, 'dist')

module.exports = [
  {
    entry: './default-import/main.js',
    output: {
      path: outputPath,
      filename: 'default-import.js',
    },
    module: {
      rules: [{ test: /\.js$/, use: 'babel-loader' }],
    },
  },
  {
    entry: './vue-sfc/main.js',
    target: 'web',
    output: {
      path: outputPath,
      filename: 'vue-sfc.cjs',
    },
    resolve: {
      extensions: ['.mjs', '.js', '.vue', '.json'],
    },
    module: {
      rules: [{ test: /\.vue$/, loader: 'vue-loader' }],
    },
    plugins: [new VueLoaderPlugin()],
  },
]
