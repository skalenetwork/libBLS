module.exports = {
    entry: {
        "encryptTransaction": "./encryptTransaction.js"
    },
    output: {
        path: __dirname,
        filename: "[name].min.js",
        library: "encryptTransaction"
    },
    module: {
        rules: [
            {
                exclude: /node_modules/,
                use: {
                    loader: "babel-loader"
                }
            }
        ]
    },
    node: {
        fs: "empty",
        child_process: "empty"
    },
    performance: { hints: false }
};