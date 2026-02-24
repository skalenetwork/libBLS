import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const ModuleFactory = require('./encrypt_node.js');

let ModulePromise = null;

function getModule() {
    if (!ModulePromise) {
        ModulePromise = ModuleFactory({
            locateFile: (filename) => {
                 if (filename.endsWith('.wasm')) {
                    const path = require('path');
                    return path.join(path.dirname(new URL(import.meta.url).pathname), 'encrypt_node.wasm');
                }
                return filename;
            }
        });
    }
    return ModulePromise;
}

export async function encryptMessage(txData, publicKey, aadTE = '', aadAES = '') {
    const Module = await getModule();
    return Module.ccall(
       'encryptMessage',
       'string',
       ['string', 'string', 'string', 'string'],
       [txData, publicKey, aadTE, aadAES]
   );
}

export async function encryptMessageDualKey(
    txData, firstPublicKey, secondPublicKey, aadTE = '', aadAES = '') {
    const Module = await getModule();
    return Module.ccall(
        'encryptMessageDualKey',
        'string',
        ['string', 'string', 'string', 'string', 'string'],
        [txData, firstPublicKey, secondPublicKey, aadTE, aadAES]
    );
}

export async function encryptMessageMockup(txData) {
    const Module = await getModule();
    return Module.ccall(
        'encryptMessageMockup',
        'string',
        ['string'],
        [txData]
    );
}
