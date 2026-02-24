const ModuleFactory = require("./encrypt_node.js");

const FIRST_BLS_PUBLIC_KEY = process.argv[2];
const SECOND_BLS_PUBLIC_KEY = process.argv[3];
const TX_DATA = process.argv[4];
const AAD_TE = process.argv[5] || "";
const AAD_AES = process.argv[6] || "";

ModuleFactory().then((Module) => {
    // Use the Module object after it is initialized
    const result = Module.ccall(
        'encryptMessageDualKey', // Name of the exported C++ function
        'string',         // Return type
        ['string', 'string', 'string', 'string', 'string'], // Argument types
        [TX_DATA, FIRST_BLS_PUBLIC_KEY, SECOND_BLS_PUBLIC_KEY, AAD_TE, AAD_AES] // Arguments
    );
    console.log(result);
}).catch((error) => {
    console.error("Failed to initialize the module:", error);
});