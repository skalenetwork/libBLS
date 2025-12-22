const ModuleFactory = require("./encrypt.js");

const FIRST_BLS_PUBLIC_KEY = process.argv[2];
const SECOND_BLS_PUBLIC_KEY = process.argv[3];
const TX_DATA = process.argv[4];
const ADDITIONAL_AUTHENTICATED_DATA = process.argv[5] || "";

ModuleFactory().then((Module) => {
    // Use the Module object after it is initialized
    const result = Module.ccall(
        'encryptMessageDualKey', // Name of the exported C++ function
        'string',         // Return type
        ['string', 'string', 'string', 'string'], // Argument types
        [TX_DATA, FIRST_BLS_PUBLIC_KEY, SECOND_BLS_PUBLIC_KEY, ADDITIONAL_AUTHENTICATED_DATA] // Arguments
    );
    console.log(result);
}).catch((error) => {
    console.error("Failed to initialize the module:", error);
});