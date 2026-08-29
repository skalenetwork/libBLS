import { createRequire } from 'module';
import { fileURLToPath } from 'url';
const require = createRequire(import.meta.url);
const ModuleFactory = require('./encrypt_node.js');
let ModulePromise = null;
function resolveModuleAssetPath(filename) {
    if (typeof filename !== 'string' || filename.length === 0) {
        throw new TypeError('filename must be a non-empty string');
    }
    const resolvedPath = fileURLToPath(new URL(filename, import.meta.url));
    if (typeof resolvedPath !== 'string' || resolvedPath.length === 0) {
        throw new Error('Failed to resolve module asset path');
    }
    return resolvedPath;
}
function getModule() {
    if (!ModulePromise) {
        ModulePromise = ModuleFactory({
            locateFile: (filename) => {
                return resolveModuleAssetPath(filename);
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
