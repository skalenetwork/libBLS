import ModuleFactory from './encrypt_web.js';
import wasmAsset from './encrypt_web.wasm';

let ModulePromise = null;

function getRuntimeBaseUrl() {
    if (typeof self !== 'undefined' && self.location && self.location.href) {
        return self.location.href;
    }
    if (typeof document !== 'undefined' && document.baseURI) {
        return document.baseURI;
    }
    return null;
}

function toAbsoluteAssetUrl(filename) {
    if (typeof filename !== 'string' || filename.length === 0) {
        throw new TypeError('filename must be a non-empty string');
    }

    const baseUrl = getRuntimeBaseUrl();
    if (!baseUrl) {
        return filename;
    }

    try {
        return new URL(filename, baseUrl).href;
    } catch {
        return filename;
    }
}

function getWasmModuleCandidate() {
    if (typeof WebAssembly === 'undefined' || typeof WebAssembly.Module === 'undefined') {
        return null;
    }

    if (wasmAsset instanceof WebAssembly.Module) {
        return wasmAsset;
    }

    if (wasmAsset && wasmAsset.default instanceof WebAssembly.Module) {
        return wasmAsset.default;
    }

    try {
        if (wasmAsset instanceof Uint8Array || wasmAsset instanceof ArrayBuffer) {
            return new WebAssembly.Module(wasmAsset);
        }

        if (wasmAsset && (wasmAsset.default instanceof Uint8Array || wasmAsset.default instanceof ArrayBuffer)) {
            return new WebAssembly.Module(wasmAsset.default);
        }
    } catch {
        // Fall through to URL-based loading below.
    }

    return null;
}

function getWasmUrlCandidate() {
    if (typeof wasmAsset === 'string' && wasmAsset.length > 0) {
        return wasmAsset;
    }

    if (wasmAsset && typeof wasmAsset.default === 'string' && wasmAsset.default.length > 0) {
        return wasmAsset.default;
    }

    if (wasmAsset && typeof wasmAsset.href === 'string' && wasmAsset.href.length > 0) {
        return wasmAsset.href;
    }

    return null;
}

function getModule() {
    if (!ModulePromise) {
        const moduleOptions = {};
        const wasmModule = getWasmModuleCandidate();
        const wasmUrl = getWasmUrlCandidate();

        if (wasmModule) {
            moduleOptions.instantiateWasm = (imports, receiveInstance) => {
                const instance = new WebAssembly.Instance(wasmModule, imports);
                receiveInstance(instance, wasmModule);
                return instance.exports;
            };
        }

        if (wasmUrl) {
            moduleOptions.locateFile = (filename) => {
                if (filename.endsWith('.wasm')) {
                    return wasmUrl;
                }

                return toAbsoluteAssetUrl(filename);
            };
        } else {
            moduleOptions.locateFile = (filename) => {
                return toAbsoluteAssetUrl(filename);
            };
        }

        ModulePromise = ModuleFactory(moduleOptions);
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
