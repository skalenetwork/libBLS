cd ../deps/emsdk
./emsdk install latest
./emsdk activate latest
source ./emsdk_env.sh
cd ../..
mkdir -p build_em
cd build_em
export LIBRARIES_ROOT=../deps/deps_inst/wasm32-emscripten/lib
emcmake cmake -DEMSCRIPTEN=ON -DBUILD_TESTS=OFF -DGMP_LIBRARY="$LIBRARIES_ROOT"/libgmp.a -DCRYPTOPP_LIBRARY="$LIBRARIES_ROOT"/libcrypto.a -DGMPXX_LIBRARY="$LIBRARIES_ROOT"/libgmpxx.a .. 
emmake make -j$(nproc)