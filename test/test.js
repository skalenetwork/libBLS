const ModuleFactory = require("./encrypt.js");

const BLS_PUBLIC_KEY = process.argv[2];
const TX_DATA = process.argv[3];

// const BLS_PUBLIC_KEY = "01794f875120054796826a296e528582adba4cf96729a97310d68fcd818b44280970fa00673e46c9399c8c00a5076061a3f269afee887b2653ce261ad249ab4d2c5544e7a0ac777e6566b9ef969c8f0f7f092e1f8fff463b957d5030c6cc77f4298d9e76f54fdf955a9879532f3189691f6a9aceee3b234f14be170c1a2d2c15";
// const TX_DATA = "109b07b3342ab2f561c22a69d9b668db552692321820ceed2e907861c72cf77f";

ModuleFactory().then((Module) => {
    // Use the Module object after it is initialized
    const result = Module.ccall(
        'encryptMessage', // Name of the exported C++ function
        'string',         // Return type
        ['string', 'string'], // Argument types
        [TX_DATA, BLS_PUBLIC_KEY] // Arguments
    );
    console.log("Encrypted Message:", result);
}).catch((error) => {
    console.error("Failed to initialize the module:", error);
});