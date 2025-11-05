# Tools for generating sample BLS-keys

Five tools to illustrate how DKG and BLS threshold signatures work.

## Overview

These tools are created to simulate all the proccess of generating private keys and signing a message until a common signature will be verified. 

After building the project, there are 5 executables:

-   `dkg_keygen` -- create individual private keys.
-   `dkg_glue` -- create common public key.
-   `sign_bls` -- create a signature.
-   `bls_glue` -- create a common signature from each signature.
-   `verify_bls` -- verify signature.

For all tools, add the flag `--help` to view input parameters and `--v` to view a verbose output.

<span style="color:blue">**Examples**</span>

        ./bls_glue --help 
        ./bls_glue --v

## Usage

1.  Go to your build directory.

2.  Generate private keys by running `./dkg_keygen` with flags `--t` and `--n`, where `n` is a number of participants in your group and `t` is a threshold number for your case. This executable outputs `j` files `BLS_keys[j].json` from 0 to `n - 1` in your build directory.

    Flag `--j` is optional and outputs each `j-th` participant's broadcast during the DKG run as json files: `data_for_j-th_participant.json`.

    Without flag `--j` all `n` sample private keys and common public key are created. Otherwise, run `dkg_keygen` `n` times for `j` from 0 to `n - 1` and then run `./dkg_glue --t --n --input /path/to/build/directory/data_for_j-th_participant.json`.

    <span style="color:blue">**Examples**</span>

    Generate keys for 3 particpants with a threshold of 2:

        ./dkg_keygen --t 2 --n 3

    Generate keys for 3 participants with a threshold of 2, and output each participant's broadcast (secret key contribution and verification vector) during DKG:

        ./dkg_keygen --t 2 --n 3 --j 0 && \
            ./dkg_keygen --t 2 --n 3 --j 1 && \
            ./dkg_keygen --t 2 --n 3 --j 2 && \
            ./dkg_glue --t 2 --n 3 \
            --input /path/to/build/data_for_0-th_participant.json \
            --input /path/to/build/data_for_1-th_participant.json \
            --input /path/to/build/data_for_2-th_participant.json

3.  To generate a common signature, execute 

         ./sign_bls --t <THRESHOLD_NUMBER> --n <PARTICIPANTS> \
             --key /path/to/build/directory/BLS_keys

    and enter a message to sign. Press `ctrl-D` to sign message. Signature is saved as `hash.json`.

     Alternatively, execute for each participant:

         ./sign_bls --t <THRESHOLD_NUMBER> \
             --n <PARTICIPANTS> \
             --j <jth_PARTICIPANT_OF_N> \
             --key /path/to/build/directory/BLS_keys \
             --output /path/to/signature/signature_from_jth_participant.json 
         

     Then to generate a common siganture execute, input all signatures:

         ./bls_glue --t <threshold> \
             --n <num_participatns> \
             --input /path/to/signature/signature_from_jth_participant.json \
             --input /path/to/signature/signature_from_jth_participant.json

     OPTIONS

     `--input` Create a file with a message to sign and pass a path to it with `--input`. Otherwise write down your message in standard input and execute `ctrl-D`.

     `--output` Specify output file name to store signature. Otherwise outputs file as `hash.json`.

     `--j` Get a file with `j-th` participant's signature. In this case specify the output json-file you want signature to be written in with flag `--output`. 

     <span style="color:blue">**Examples**</span>

     Generate a common signature from BLS keys and sign message `data.in`

         ./sign_bls --t 2 --n 3 \
             --input /path/to/message/data.in \
             --key /path/to/keys/BLS_keys 

      Generate signatures from each participant, output each as a JSON, and then generate a common signature:

         ./sign_bls --t 2 --n 3 --j 0 \
             --key /path/to/keys/BLS_keys \
             --input /path/to/message/data.in \
             --output /path/to/signature/signature_from_0th_participant.json && \
         ./sign_bls --t 2 --n 3 --j 1 \
             --key /path/to/keys/BLS_keys \
             --input /path/to/message/data.in \
             --output /path/to/signature/signature_from_1th_participant.json && \
         ./bls_glue --t 2 --n 3 \
             --input /path/to/build/directory/signature_from_0th_participant.json \
             --input /path/to/build/directory/signature_from_1th_participant.json

4.  Verify a signature by entering `./verify_bls --t <threshold> --n <num_participants>`. Flag `--input` is optional - you can pass signature to the tool either via standard input or a json file.

    <span style="color:blue">**Example**</span>

        ./verify_bls --t 2 --n 3 --input /path/to/signature/signature.json

5. Generate all private and public keys as well as common public key: `./generate_key_system --t <threshold> --n <num_participants>`. Flag `--output` is optional.

    <span style="color:blue">**Example**</span>

        ./generate_key_system --t 3 --n 4 --output /path/to/file/output.json
