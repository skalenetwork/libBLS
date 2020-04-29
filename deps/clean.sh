#!/bin/bash

# colors/basic
COLOR_RESET='\033[0m' # No Color
COLOR_BLACK='\033[0;30m'
COLOR_DARK_GRAY='\033[1;30m'
COLOR_BLUE='\033[0;34m'
COLOR_LIGHT_BLUE='\033[1;34m'
COLOR_GREEN='\033[0;32m'
COLOR_LIGHT_GREEN='\033[1;32m'
COLOR_CYAN='\033[0;36m'
COLOR_LIGHT_CYAN='\033[1;36m'
COLOR_RED='\033[0;31m'
COLOR_LIGHT_RED='\033[1;31m'
COLOR_MAGENTA='\033[0;35m'
COLOR_LIGHT_MAGENTA='\033[1;35m'
COLOR_BROWN='\033[0;33m'
COLOR_YELLOW='\033[1;33m'
COLOR_LIGHT_GRAY='\033[0;37m'
COLOR_WHITE='\033[1;37m'
# colors/variables
COLOR_ERROR="${COLOR_RED}"
COLOR_WARN="${COLOR_YELLOW}"
COLOR_ATTENTION="${COLOR_LIGHT_CYAN}"
COLOR_SUCCESS="${COLOR_GREEN}"
COLOR_INFO="${COLOR_BLUE}"
COLOR_NOTICE="${COLOR_MAGENTA}"
COLOR_DOTS="${COLOR_DARK_GRAY}"
COLOR_SEPARATOR="${COLOR_LIGHT_MAGENTA}"
COLOR_VAR_NAME="${COLOR_BLUE}"
COLOR_VAR_DESC="${COLOR_BROWN}"
COLOR_VAR_VAL="${COLOR_LIGHT_GRAY}"
COLOR_PROJECT_NAME="${COLOR_LIGHT_BLUE}"

echo -e "${COLOR_BLACK}${COLOR_DARK_GRAY}${COLOR_BLUE}${COLOR_LIGHT_BLUE}${COLOR_GREEN}${COLOR_LIGHT_GREEN}${COLOR_CYAN}${COLOR_LIGHT_CYAN}${COLOR_RED}${COLOR_LIGHT_RED}${COLOR_MAGENTA}${COLOR_LIGHT_MAGENTA}${COLOR_BROWN}${COLOR_YELLOW}${COLOR_LIGHT_GRAY}${COLOR_WHITE}${COLOR_ERROR}${COLOR_WARN}${COLOR_ATTENTION}${COLOR_SUCCESS}${COLOR_INFO}${COLOR_NOTICE}${COLOR_DOTS}${COLOR_SEPARATOR}${COLOR_VAR_NAME}${COLOR_VAR_DESC}${COLOR_VAR_VAL}${COLOR_PROJECT_NAME}${COLOR_RESET}" &> /dev/null

#
# move values of command line arguments into variables
#
argc=$#
argv=($@)
for (( j=0; j<argc; j++ )); do
	#echo ${argv[j]}
	PARAM=$(echo "${argv[j]}" | awk -F= '{print $1}')
	VALUE=$(echo "${argv[j]}" | awk -F= '{print $2}')
	#echo ${PARAM}
	#echo ${VALUE}
	export "${PARAM}"="${VALUE}"
done
#
#
#

if [ -z "${ARCH}" ];
then
	# if we don't have explicit ARCH=something from command line arguments
	ARCH="x86_or_x64"
else
	if [ "$ARCH" = "arm" ];
	then
		ARCH="arm"
	else
		ARCH="x86_or_x64"
	fi
fi
if [ "$ARM" = "1" ];
then
	# if we have explicit ARM=1 from command line arguments
	ARCH="arm"
fi

# detect system name and number of CPU cores
export UNIX_SYSTEM_NAME=$(uname -s)
export NUMBER_OF_CPU_CORES=1
if [ "$UNIX_SYSTEM_NAME" = "Linux" ];
then
	export NUMBER_OF_CPU_CORES=$(grep -c ^processor /proc/cpuinfo)
	export READLINK=readlink
	export SO_EXT=so
fi
if [ "$UNIX_SYSTEM_NAME" = "Darwin" ];
then
	#export NUMBER_OF_CPU_CORES=$(system_profiler | awk '/Number Of CPUs/{print $4}{next;}')
	export NUMBER_OF_CPU_CORES=$(sysctl -n hw.ncpu)
	# required -> brew install coreutils
	export READLINK=greadlink
	export SO_EXT=dylib
fi

# detect working directories, change if needed
WORKING_DIR_OLD=$(pwd)
cd "$(dirname "$0")"
WORKING_DIR_NEW="$(dirname "$0")"
WORKING_DIR_OLD=$("$READLINK" -f "$WORKING_DIR_OLD")
WORKING_DIR_NEW=$("$READLINK" -f "$WORKING_DIR_NEW")
cd "$WORKING_DIR_NEW"

echo -e " "
echo -e "${COLOR_LIGHT_MAGENTA}BLS dependencies cleanup actions...${COLOR_RESET}"

echo -e "${COLOR_VAR_NAME}WORKING_DIR_OLD${COLOR_DOTS}........${COLOR_VAR_DESC}Started in directory${COLOR_DOTS}...................${COLOR_VAR_VAL}${WORKING_DIR_OLD}${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WORKING_DIR_NEW${COLOR_DOTS}........${COLOR_VAR_DESC}Switched to directory${COLOR_DOTS}..................${COLOR_VAR_VAL}${WORKING_DIR_NEW}${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}UNIX_SYSTEM_NAME${COLOR_DOTS}.......${COLOR_VAR_DESC}Running on host${COLOR_DOTS}........................${COLOR_VAR_VAL}${UNIX_SYSTEM_NAME}${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}NUMBER_OF_CPU_CORES${COLOR_DOTS}....${COLOR_VAR_DESC}Running on host having CPU cores${COLOR_DOTS}.......${COLOR_VAR_VAL}${NUMBER_OF_CPU_CORES}${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}ARCH${COLOR_DOTS}...................${COLOR_VAR_DESC}Building for architecture${COLOR_DOTS}..............${COLOR_VAR_VAL}$ARCH${COLOR_RESET}"

#echo "Cleaning \"top\" libraries..."
echo "Cleaning \"deps_inst\" folder..."
rm -rf ./deps_inst
rm -rf ./build
echo "Cleaning archive files..."
rm -f ./*.tar.gz
rm -f ./*.zip
echo "Cleaning upacked library folders..."
rm -rf ./libiconv-1.15
rm -rf ./zlib
rm -rf ./openssl
rm -rf ./curl
rm -rf ./libuv
rm -rf ./libwebsockets
rm -rf ./boost_1_68_0
rm -rf ./argtable2
rm -rf ./nettle-2.0
rm -rf ./nettle-3.4.1
rm -rf ./gnutls-3.6.5
rm -rf ./libmicrohttpd
rm -rf ./jsoncpp
rm -rf ./libjson-rpc-cpp
rm -rf ./libcryptopp
# rm -rf ./bzip2
# rm -rf ./lzma
# rm -rf ./SDL2-2.0.7
# rm -rf ./SDL2_ttf-2.0.14
# rm -rf ./shine
# rm -rf ./readline-7.0
# rm -rf ./libxml2-2.9.7
# rm -rf ./libarchive-3.3.2
# rm -rf ./libev
# rm -rf ./libevent
# rm -rf l./ibwebsockets
# rm -rf ./gtest
rm -rf ./gmp-6.1.2
rm -rf ./libff
rm -rf ./pbc
echo "Done (all clean)."

#finish
cd "$WORKING_DIR_OLD"
