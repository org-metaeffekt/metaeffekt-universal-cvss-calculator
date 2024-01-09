const path = require('path');

module.exports = {
    mode: 'production',
    entry: './src/index.ts',
    optimization: {
    },
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                use: 'ts-loader',
                exclude: /node_modules/,
            },
        ],
    },
    resolve: {
        extensions: ['.tsx', '.ts', '.js'],
    },
    output: {
        filename: 'ae-cvss-calculator.js',
        path: path.resolve(__dirname, 'dist'),
        library: 'CvssCalculator',
        libraryTarget: 'umd',
        globalObject: 'this',
    },
};
