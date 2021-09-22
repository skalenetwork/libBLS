cd ../deps/emsdk
./emsdk install latest
./emsdk activate latest
source ./emsdk_env.sh
cd ../../build_em
emmake cmake .. -DEMSCRIPTEN=ON
emmake make te