#!bin/bash

#edit this code before use it

./dkg_keygen --t 1 --n 2

cat data.in | ./sign_bls --t 1 --n 2 --key <your_path>

./verify_bls --t 1 --n 2