import { createRequire } from 'module';
import { fileURLToPath } from 'url';
const require = createRequire(import.meta.url);
const ModuleFactory = require('./encrypt_node.js');

let ModulePromise = null;

function getModule() {
    if (!ModulePromise) {
        ModulePromise = ModuleFactory({
            locateFile: (filename) => {
                const resolvedUrl = new URL(filename, import.meta.url);
                return resolvedUrl.protocol === 'file:'
                    ? fileURLToPath(resolvedUrl)
                    : resolvedUrl.href;
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
