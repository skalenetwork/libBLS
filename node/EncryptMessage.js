const ModuleFactory = require('./encrypt.js');

async function encryptMessage(txData, publicKey) {
    const Module = await ModuleFactory();
    return Module.ccall(
        'encryptMessage', // Name of the exported C++ function
        'string',         // Return type
        ['string', 'string'], // Argument types
        [txData, publicKey] // Arguments
    );
}

async function encryptMessageDualKey(txData, firstPublicKey, secondPublicKey) {
    const Module = await ModuleFactory();
    return Module.ccall(
        'encryptMessageDualKey', // Name of the exported C++ function
        'string',         // Return type
        ['string', 'string', 'string'], // Argument types
        [txData, firstPublicKey, secondPublicKey] // Arguments
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
