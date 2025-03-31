const ModuleFactory = require("./encrypt.js");

const BLS_PUBLIC_KEY = process.argv[2];
const TX_DATA = process.argv[3];

ModuleFactory().then((Module) => {
    // Use the Module object after it is initialized
    const result = Module.ccall(
        'encryptMessage', // Name of the exported C++ function
        'string',         // Return type
        ['string', 'string'], // Argument types
        [TX_DATA, BLS_PUBLIC_KEY] // Arguments
    );
    console.log(result);
}).catch((error) => {
    console.error("Failed to initialize the module:", error);
});