const path = require('path');
const ModuleFactory = require('./encrypt_node.js');

let ModulePromise = null;

function getModule() {
    if (!ModulePromise) {
        ModulePromise = ModuleFactory({
            locateFile: (filename) => {
                // Should return absolute path to encrypt_node.wasm
                if (filename.endsWith('.wasm')) {
                    return path.join(__dirname, 'encrypt_node.wasm');
                }
                return path.join(__dirname, filename);
            }
        });
    }
    return ModulePromise;
}

async function encryptMessage(txData, publicKey, aadTE = '', aadAES = '') {
    const Module = await getModule();
    return Module.ccall(
        'encryptMessage', // Name of the exported C++ function
        'string',         // Return type
        ['string', 'string', 'string', 'string'], // Argument types
        [txData, publicKey, aadTE, aadAES] // Arguments
    );
}

async function encryptMessageDualKey(
    txData, firstPublicKey, secondPublicKey, aadTE = '', aadAES = '') {
    const Module = await getModule();
    return Module.ccall(
        'encryptMessageDualKey', // Name of the exported C++ function
        'string',         // Return type
        ['string', 'string', 'string', 'string', 'string'], // Argument types
        [txData, firstPublicKey, secondPublicKey, aadTE, aadAES] // Arguments
    );
}

async function encryptMessageMockup(txData) {
    const Module = await getModule();
    return Module.ccall(
        'encryptMessageMockup', // Name of the exported C++ function
        'string',         // Return type
        ['string'], // Argument types
        [txData] // Arguments
    );
}

module.exports = { encryptMessage, encryptMessageDualKey, encryptMessageMockup };
