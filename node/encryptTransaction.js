const Web3 = require("web3");

async function get_common_bls_public_key( eth ) {    
    // hardcoded address and function signature
    let web3 = new Web3( eth.currentProvider );
    // TODO: check if it works ok with zeros in coordinates
    return await web3.eth.call({"to": "0xd2aaa00200000000000000000000000000000000", "data": "0x554ef7a6"});
}

async function encrypt_data( data, common_bls_public_key ) {
    var factory = require("./encrypt.js");

    var encryptedMesage = "";
    var instance = await factory();
    var ptrData = instance.allocate(instance.intArrayFromString(data), instance.ALLOC_NORMAL);
    var ptrKey = instance.allocate(instance.intArrayFromString(common_bls_public_key), instance.ALLOC_NORMAL);
    var result = instance.ccall("encryptMessage", "number", ["number", "number"], [ptrData, ptrKey]);
    var resValue = instance.UTF8ToString(result);
    instance._free(ptrKey);
    instance._free(ptrData);
    encryptedMesage = resValue;
    return encryptedMesage;
}

async function sendData( eth, to, data ) {
    let web3 = new Web3( eth.currentProvider );
    
    let accs = await web3.eth.getAccounts();
    let address = accs[0];
    let nonce = await web3.eth.getTransactionCount( address );
    let chainId = await web3.eth.getChainId();
    
    let tx = {
        from: address,
        data: data,
        gas: 1000000,
        to: to,
        nonce: nonce,
        chainId: chainId
    };

    return await web3.eth.sendTransaction(tx);
}

async function encryptAndSend(eth, to, data) {
    let bls_key = await get_common_bls_public_key( eth );
    let encrypted_data = await encrypt_data( data, bls_key.substring(2) );
    let res = await sendData(eth, to, encrypted_data);
    return res;
}


module.exports.encryptAndSend = encryptAndSend
module.exports.encrypt_data = encrypt_data
module.exports.get_common_bls_public_key = get_common_bls_public_key