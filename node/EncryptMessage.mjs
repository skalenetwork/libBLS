import ModuleFactory from './encrypt_web.js';

let ModulePromise = null;

function getModule() {
    if (!ModulePromise) {
        const wasmUrl = new URL('encrypt_web.wasm', import.meta.url).href;
        ModulePromise = ModuleFactory({
            locateFile: (path) => {
                if (path.endsWith('.wasm')) {
                    return wasmUrl;
                }
                return path;
            }
        });
    }
    return ModulePromise;
}

export async function encryptMessage(txData, publicKey, aadTE = '', aadAES = '') {
    const Module = await getModule();
    return Module.ccall(
        'encryptMessage', // Name of the exported C++ function
        'string',         // Return type
        ['string', 'string', 'string', 'string'], // Argument types
        [txData, publicKey, aadTE, aadAES] // Arguments
    );
}

export async function encryptMessageDualKey(
    txData, firstPublicKey, secondPublicKey, aadTE = '', aadAES = '') {
    const Module = await getModule();
    return Module.ccall(
        'encryptMessageDualKey', // Name of the exported C++ function
        'string',         // Return type
        ['string', 'string', 'string', 'string', 'string'], // Argument types
        [txData, firstPublicKey, secondPublicKey, aadTE, aadAES] // Arguments
    );
}

export async function encryptMessageMockup(txData) {
    const Module = await getModule();
    return Module.ccall(
        'encryptMessageMockup', // Name of the exported C++ function
        'string',         // Return type
        ['string'], // Argument types
        [txData] // Arguments
    );
}
