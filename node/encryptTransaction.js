const Web3 = require('web3');
// var factory = require('./encrypt.js');
// var encryptedMesage = "";

async function get_common_bls_public_key( eth ) {    
    // hardcoded address and function signature
    let web3 = new Web3( eth.currentProvider );
    return await web3.eth.call({'to': '0xd2aaa00200000000000000000000000000000000', 'data': '0x554ef7a6'});
}

// function encrypt_data( data, common_bls_public_key ) {
//     // let encryptMessage = Module.cwrap('encryptMessage', 'string', ['string', 'string'])( data, common_bls_public_key );
//     // return Module.(data, common_bls_public_key);
//     // return Module.ccall('encryptMessage', 'string', 'string', ['string'], [data, common_bls_public_key]);
//     factory().then((instance) => {
//         encryptedMesage = instance.ccall("encryptMessage"); // using ccall etc. also work
//       });
//       return encryptedMesage;
// }

// async function encryptTx( eth, to, data ) {
//     let web3 = new Web3( eth.currentProvider );

//     let common_bls_public_key_array = await get_common_bls_public_key( web3 );
    
//     let encrypted_data = encrypt_data( data, common_bls_public_key_array );
    
//     let nonce = await web3.eth.getTransacationCount( address );
//     let chainId = await web3.eth.getChainId();
//     let address = await web3.eth.accounts()[0];
//     console.log(address);
    
//     let tx = {
//         from: address,
//         data: encrypted_data,
//         gas: gas,
//         to: to,
//         nonce: nonce,
//         chainId: chainId
//     };

//     let privateKey = 0;

//     let signedTx = await web3.eth.accounts.signTransaction(tx, privateKey);
//     return await web3.eth.sendSignedTransaction(signedTx.rawTransaction);
// }


module.exports.get_common_bls_public_key = get_common_bls_public_key
// module.exports.encryptTx = encryptTx