# Tools for generating sample BLS-keys

5 tools to illustrate how DKG and BLS threshold signatures work.

## Overview

These 5 tools are created to simmulate all the proccess of generating private keys and signing a message until a common signature will be verified. 

After building the project you get 5 executables named `dkg_keygen`, `dkg_glue`, `sign_bls`, `bls_glue`, `verify_bls`.

You can proceed the process above as follows:
1. 	Go to your build directory.
2.  For all 5 tools you can run `./tools_name --help` to see what input parameters you need and `./tools_name --v` to get a verbose output.
	Example : `./bls_glue --help` and `./bls_glue --v`.
3. 	You can generate private keys all in one time by running `./dkg_keygen` with flags `--t` and `--n`, where `n` is a number of participants in your group and `t` is a threshold number for your case. Flag `--j` is optional - in case you want to go deeper in details you can run it and you will get a file with some data that `j-th` participant broadcasts during the DKG run. File's name is `data_for_j-th_participant.json`. If you ran `dkg_keygen` without flag `--j` all `n` sample private keys and common public key are created. Otherwise, run `dkg_keygen` `n` times for `j` from 0 to `n - 1` and then run `./dkg_glue --t --n --input /path/to/build/directory/data_for_j-th_participant.json`. As output of this executable you will get a file "BLS_keysj.json" for `j` from 0 to `n - 1` in your build directory.
	Example : `./dkg_keygen --t 2 --n 3` or `./dkg_keygen --t 2 --n 3 --j 0 && ./dkg_keygen --t 2 --n 3 --j 1 && ./dkg_keygen --t 2 --n 3 --j 2 && ./dkg_glue --t 2 --n 3 --input /path/to/build/directory/data_for_0-th_participant.json --input /path/to/build/directory/data_for_1-th_participant.json --input /path/to/build/directory/data_for_2-th_participant.json`.
4.	To get a common signature run `./sign_bls --t --n --key path/to/build/directory/BLS_keys`. Flag `--input` is optional - you can create a file with a message to sign and pass a path to it with `--input` or write down your message in standart input. Flag `--j` is optional too - in case you want to go deeper in details you can run it and you will get a file with `j-th` participant's signature. In this case specify the output json-file you want signature to be written in with flag `--output`. After you ran `./sign_bls --t --n --key path/to/build/directory/BLS_keys --output /your/path/to/signature/signature_from_jth_participant.json` for `n` times you can run `./bls_glue --t --n --input /path/to/signature/signature_from_jth_participant.json` and get a common siganture.
Example : `./sign_bls --t 2 --n 3 --input /your/path/to/message/data.in --key /your/path/to/keys/BLS_keys` or `./sign_bls --t 2 --n 3 --j 0 --key /your/path/to/keys/BLS_keys --output /your/path/to/signature/signature_from_0th_participant.json && ./sign_bls --t 2 --n 3 --j 1 --key /your/path/to/keys/BLS_keys --output /your/path/to/signature/signature_from_1th_participant.json && ./bls_glue --t 2 --n 3 --input /path/to/build/directory/signature_from_0th_participant.json --input /path/to/build/directory/signature_from_1th_participant.json`.
5.	Verify your signature by running `./verify_bls --t --n`. Flag `--input` is optional - you can pass signature to the tool either via standard input or a json-file.
	Example : `./verify_bls --t 2 --n 3 --input /your/path/to/signature/signature.json`