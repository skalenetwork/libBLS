const ModuleFactory = require('./encrypt.js');

async function encryptMessage(txData, publicKey, AADAES = '', AADTE = '') {
    const Module = await ModuleFactory();
    return Module.ccall(
        'encryptMessage', // Name of the exported C++ function
        'string',         // Return type
        ['string', 'string', 'string', 'string'], // Argument types
        [txData, publicKey, AADAES, AADTE] // Arguments
    );
}

async function encryptMessageDualKey(
    txData, firstPublicKey, secondPublicKey, AADAES = '', AADTE = '') {
    const Module = await ModuleFactory();
    return Module.ccall(
        'encryptMessageDualKey', // Name of the exported C++ function
        'string',         // Return type
        ['string', 'string', 'string', 'string', 'string'], // Argument types
        [txData, firstPublicKey, secondPublicKey, AADAES, AADTE] // Arguments
    );
}

async function encryptMessageMockup(txData) {
    const Module = await ModuleFactory();
    return Module.ccall(
        'encryptMessageMockup', // Name of the exported C++ function
        'string',         // Return type
        ['string'], // Argument types
        [txData] // Arguments
    );
}

module.exports = { encryptMessage, encryptMessageDualKey, encryptMessageMockup };
