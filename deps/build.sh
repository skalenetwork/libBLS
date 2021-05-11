#!/bin/bash

env_save_original() {
	export > ./saved_environment_on_startup.txt
}

env_restore_original() {
	#env_clear_all
	source ./saved_environment_on_startup.txt
}

env_save_original

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
	export READLINK=/usr/local/bin/greadlink
	export SO_EXT=dylib
fi

# detect working directories, change if needed
WORKING_DIR_OLD=$(pwd)
WORKING_DIR_NEW="$(dirname "$0")"
WORKING_DIR_OLD=$("$READLINK" -f "$WORKING_DIR_OLD")
WORKING_DIR_NEW=$("$READLINK" -f "$WORKING_DIR_NEW")
cd "$WORKING_DIR_NEW"

#
# MUST HAVE: make, git, svn, nasm, yasm, wget, cmake, ccmake, libtool, libtool_bin, autogen, automake, autopoint, gperf, awk (mawk or gawk), sed, shtool, texinfo, pkg-config
#
#

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

simple_find_tool_program () { # program_name, var_name_to_export_full_path, is_optional("yes" or "no")
	echo -e "checking for tool program: $1"
	#echo $1
	#echo $2
	#
	TMP_P=$(which "$1")
	TMP_CMD="export $2=$TMP_P"
	#
	$TMP_CMD
	TMP_CMD="echo ${!2}"
	echo -e "....will invoke.......... $TMP_CMD"
	TMP_VAL="$($TMP_CMD)"
	echo -e "....got invoke result.... $TMP_VAL"
	if [ "$TMP_VAL" = "" ];
	then
		TMP_CMD="export $2=/usr/local/bin/$1"
		$TMP_CMD
		TMP_CMD="echo ${!2}"
		echo -e "....will invoke.......... $TMP_CMD"
		TMP_VAL="$($TMP_CMD)"
		echo -e "....got invoke result.... $TMP_VAL"
		if [ -f "$TMP_VAL" ];
		then
			echo -e "....${COLOR_SUCCESS}SUCCESS: $2 found as $TMP_VAL" "${COLOR_RESET}"
			return 0
		fi
		#TMP_CMD="export $2=/opt/local/bin/$1"
		#$TMP_CMD
		#TMP_CMD="echo ${!2}"
		#TMP_VAL="$($TMP_CMD)"
		#if [ -f "$TMP_VAL" ];
		#then
		#	#echo -e "${COLOR_SUCCESS}SUCCESS: $2 found as $TMP_VAL" "${COLOR_RESET}"
		#	return 0
		#fi
	fi
	if [ -f "$TMP_VAL" ];
	then
		echo -e "....${COLOR_SUCCESS}SUCCESS: $2 found as $TMP_VAL" "${COLOR_RESET}"
		return 0
	fi
	if [ "$3" = "yes" ];
	then
		return 0
	fi
	echo -e "....${COLOR_ERROR}error: $2 tool was not found by deps build script${COLOR_RESET}"
	cd "$WORKING_DIR_OLD"
	env_restore_original
	exit 255
}

simple_find_tool_program "make" "MAKE" "no"
simple_find_tool_program "makeinfo" "MAKEINFO" "no"
simple_find_tool_program "cmake" "CMAKE" "no"
#simple_find_tool_program "ccmake" "CCMAKE" "yes"
#simple_find_tool_program "scons" "SCONS" "yes"
simple_find_tool_program "wget" "WGET" "no"
simple_find_tool_program "autoconf" "AUTOCONF" "no"
###simple_find_tool_program "autogen" "AUTOGEN" "yes"
simple_find_tool_program "automake" "AUTOMAKE" "yes"
simple_find_tool_program "m4" "M4" "yes"
if [ ! "$UNIX_SYSTEM_NAME" = "Darwin" ];
then
	simple_find_tool_program "libtoolize" "LIBTOOLIZE" "no"
else
	simple_find_tool_program "glibtoolize" "LIBTOOLIZE" "no"
fi
simple_find_tool_program "pkg-config" "PKG_CONFIG" "no"
if [ ! "$UNIX_SYSTEM_NAME" = "Darwin" ];
then
  simple_find_tool_program "yasm" "YASM" "no"
fi
simple_find_tool_program "wget" "WGET" "no"

echo -e "${COLOR_SEPARATOR}===================================================================${COLOR_RESET}"
echo -e "${COLOR_YELLOW}BLS dependencies build actions...${COLOR_RESET}"
echo -e "${COLOR_SEPARATOR}==================== ${COLOR_PROJECT_NAME}PREPARE BUILD${COLOR_SEPARATOR} ================================${COLOR_RESET}"

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
#
TOP_CMAKE_BUILD_TYPE="Release"
if [ "$DEBUG" = "1" ];
then
	DEBUG=1
	TOP_CMAKE_BUILD_TYPE="Debug"
	DEBUG_D="d"
	CONF_DEBUG_OPTIONS="--enable-debug"
else
	DEBUG=0
	DEBUG_D=""
	CONF_DEBUG_OPTIONS=""
fi
#
if [ -z "${USE_LLVM}" ];
then
	USE_LLVM="0"
fi
if [ "$ARCH" = "arm" ];
then
	USE_LLVM="0"
fi
if [ "$USE_LLVM" != "0" ];
then
	USE_LLVM="1"
fi

if [ -z "${WITH_GTEST}" ];
then
	WITH_GTEST=0
else
	WITH_GTEST=1
fi

export CFLAGS="$CFLAGS -fPIC"
export CXXFLAGS="$CXXFLAGS -fPIC"
WITH_OPENSSL="yes"

WITH_BOOST="yes"
if [ "$SKALED_DEPS_CHAIN" = "1" ];
then
	WITH_BOOST="no"
fi
# if [ "$CONSENSUS_DEPS_CHAIN" = "1" ];
# then
# 	WITH_BOOST="no"
# fi

WITH_FF="yes"
WITH_GMP="yes"
WITH_PBC="yes"

if [ -z "${PARALLEL_COUNT}" ];
then
	PARALLEL_COUNT=$NUMBER_OF_CPU_CORES
fi
if [[ $PARALLEL_COUNT -gt 1 ]];
then
	PARALLEL_MAKE_OPTIONS=" -j $PARALLEL_COUNT "
else
	PARALLEL_MAKE_OPTIONS=""
fi

export CUSTOM_BUILD_ROOT=$PWD
export INSTALL_ROOT_RELATIVE="$CUSTOM_BUILD_ROOT/deps_inst/$ARCH"
mkdir -p "$INSTALL_ROOT_RELATIVE"
export INSTALL_ROOT=$("$READLINK" -f "$INSTALL_ROOT_RELATIVE")
export SOURCES_ROOT=$("$READLINK" -f "$CUSTOM_BUILD_ROOT")
export PREDOWNLOADED_ROOT=$("$READLINK" -f "$CUSTOM_BUILD_ROOT/pre_downloaded")
export LIBRARIES_ROOT="$INSTALL_ROOT/lib"
mkdir -p "$SOURCES_ROOT"
mkdir -p "$INSTALL_ROOT"
mkdir -p "$INSTALL_ROOT/share"
mkdir -p "$INSTALL_ROOT/share/pkgconfig"

# we need this custom prefix bin dir in PATH for tools like gpg-error-config which we build here
export PATH=$PATH:$INSTALL_ROOT/bin

export TOOLCHAINS_PATH=/usr/local/toolchains
export TOOLCHAINS_DOWNLOADED_PATH=$TOOLCHAINS_PATH/downloads

export ARM_TOOLCHAIN_NAME=gcc7.2-arm
export ARM_GCC_VER=7.2.0

#export ARM_TOOLCHAIN_NAME=gcc4.8-arm
#export ARM_GCC_VER=4.8.4

export ARM_TOOLCHAIN_PATH=$TOOLCHAINS_PATH/$ARM_TOOLCHAIN_NAME

export ADDITIONAL_INCLUDES="-I$INSTALL_ROOT/include"
export ADDITIONAL_LIBRARIES="-L$INSTALL_ROOT/lib"
export TOOLCHAIN=no

export CFLAGS=" -fPIC ${CFLAGS}"

if [[ ! -z $CXX ]];
then
    SET_CXX=$CXX
fi
if [[ ! -z $CC ]];
then
    SET_CC=$CC
fi

if [ "$ARCH" = "x86_or_x64" ];
then
	export CMAKE_CROSSCOMPILING_OPTS="-DCMAKE_POSITION_INDEPENDENT_CODE=ON"
	#export MAKE_CROSSCOMPILING_OPTS=""
	export CONF_CROSSCOMPILING_OPTS_GENERIC=""
	export CONF_CROSSCOMPILING_OPTS_GMP="--host=haswell-pc-linux-gnu"
	export CONF_CROSSCOMPILING_OPTS_VORBIS=""
	export CONF_CROSSCOMPILING_OPTS_CURL=""
	export CONF_CROSSCOMPILING_OPTS_BOOST=""
	export CONF_CROSSCOMPILING_OPTS_VPX=""
	export CONF_CROSSCOMPILING_OPTS_X264=""
	export CONF_CROSSCOMPILING_OPTS_FFMPEG=""
	#export CC=$(which gcc)
	#export CXX=$(which g++)
	if [ "$USE_LLVM" = "1" ];
	then
		export CC=$(which clang)
		export CXX=$(which clang++)
		export AS=$(which llvm-as)
		export AR=$(which llvm-ar)
		#export LD=$(which llvm-ld)
		export LD=$(which lld)
		export RANLIB=$(which llvm-ranlib)
		export OBJCOPY=$(which llvm-objcopy)
		export OBJDUMP=$(which llvm-objdump)
		export NM=$(which llvm-nm)
	else
		if [ "$UNIX_SYSTEM_NAME" = "Linux" ];
		then
			export CC=$(which gcc-7)
			if [ -z "${CC}" ];
			then
				export CC=$(which gcc)
			fi
			export CXX=$(which g++-7)
			if [ -z "${CXX}" ];
			then
				export CXX=$(which g++)
			fi
		else
			export CC=$(which gcc)
			export CXX=$(which g++)
		fi
		export AS=$(which as)
		export AR=$(which ar)
		export LD=$(which ld)
		export RANLIB=$(which ranlib)
		export OBJCOPY=$(which objcopy)
		export OBJDUMP=$(which objdump)
		export NM=$(which nm)
	fi
	export STRIP=$(which strip)
	export UPNP_DISABLE_LARGE_FILE_SUPPORT=""
else
	export HELPER_ARM_TOOLCHAIN_NAME=arm-linux-gnueabihf

	if [ ! -d "$ARM_TOOLCHAIN_PATH" ];
	then
		export ARM_TOOLCHAIN_LINK="https://drive.google.com/file/d/11z-0nJpOBECycQxTpBxLC9cwXwYCFOjt/view?usp=sharing"
		export ARM_TOOLCHAIN_INTERNAL_LINK="http://store.skale.lan/files/gcc7.2-arm-toolchaine.tar.gz"
		export ARM_TOOLCHAIN_ARCH_NAME=$ARM_TOOLCHAIN_NAME-toolchaine.tar.gz

		mkdir -p $TOOLCHAINS_PATH
		if [ ! -d $TOOLCHAINS_PATH ];
		then
			echo " "
			echo -e "${COLOR_SEPARATOR}=================================================${COLOR_RESET}"
			echo -e "${COLOR_ERROR}error: ${COLOR_VAR_VAL}${TOOLCHAINS_PATH}${COLOR_ERROR} folder not created!${COLOR_RESET}"
			echo -e "${COLOR_ERROR}Create ${COLOR_VAR_VAL}${TOOLCHAINS_PATH}${COLOR_ERROR} folder and give permissions for writing here to current user.${COLOR_RESET}"
			echo -e "${COLOR_SEPARATOR}=================================================${COLOR_RESET}"
			cd "$WORKING_DIR_OLD"
			env_restore_original
			exit 255
		fi

		mkdir -p $TOOLCHAINS_DOWNLOADED_PATH
		cd "$TOOLCHAINS_DOWNLOADED_PATH"
		wget $ARM_TOOLCHAIN_INTERNAL_LINK

		if [ ! -f $ARM_TOOLCHAIN_ARCH_NAME ];
		then
			echo " "
			echo -e "${COLOR_SEPARATOR}=================================================${COLOR_RESET}"
			echo -e "${COLOR_ERROR}Cannot download toolchain archive: ${COLOR_VAR_VAL}$ARM_TOOLCHAIN_ARCH_NAME${COLOR_RESET}"
			echo -e "${COLOR_ERROR}Try download: ${COLOR_VAR_VAL}${ARM_TOOLCHAIN_LINK}${COLOR_RESET}"
			echo -e "${COLOR_ERROR}Mirror: ${COLOR_VAR_VAL}${ARM_TOOLCHAIN_INTERNAL_LINK}${COLOR_RESET}"
			echo -e "${COLOR_ERROR}Copy ${COLOR_VAR_VAL}${ARM_TOOLCHAIN_ARCH_NAME}${COLOR_ERROR} to ${COLOR_VAR_VAL}${TOOLCHAINS_DOWNLOADED_PATH}${COLOR_RESET}"
			echo -e "${COLOR_SEPARATOR}=================================================${COLOR_RESET}"
			cd "$WORKING_DIR_OLD"
			env_restore_original
			exit 255
		fi

		mkdir -p $ARM_TOOLCHAIN_PATH
		cd "$ARM_TOOLCHAIN_PATH"
		tar -zxvf $TOOLCHAINS_DOWNLOADED_PATH/$ARM_TOOLCHAIN_ARCH_NAME

		if [ ! -d "$ARM_TOOLCHAIN_PATH/arm-linux-gnueabihf/bin" ];
		then
			echo " "
			echo -e "${COLOR_SEPARATOR}=================================================${COLOR_RESET}"
			echo -e "${COLOR_ERROR}Cannot unpack toolchain archive: ${COLOR_VAR_VAL}$TOOLCHAINS_DOWNLOADED_PATH${COLOR_ERROR}/${COLOR_VAR_VAL}$TOOLCHAIN_ARCH_NAME${COLOR_RESET}"
			echo -e "${COLOR_SEPARATOR}=================================================${COLOR_RESET}"
			cd "$WORKING_DIR_OLD"
			env_restore_original
			exit 255
		fi

		echo -e "${COLOR_SEPARATOR}============== ${COLOR_PROJECT_NAME}TOOLCHAINE UNPACKED${COLOR_SEPARATOR} ==============${COLOR_RESET}"
	fi

	set -e -o pipefail

	export TOOLCHAIN=$ARM_TOOLCHAIN_NAME

	export ARM_BOOST_PATH=$ARM_TOOLCHAIN_PATH/boost
#	export PATH="$ARM_TOOLCHAIN_PATH/arm-linux-gnueabihf/bin:$ARM_TOOLCHAIN_PATH/bin:$PATH"
	export LD_LIBRARY_PATH="$ARM_TOOLCHAIN_PATH/arm-linux-gnueabihf/lib:$ARM_TOOLCHAIN_PATH/lib:$ARM_TOOLCHAIN_PATH/lib/gcc/arm-linux-gnueabihf/$ARM_GCC_VER/plugin:$LD_LIBRARY_PATH"

	export CC="$ARM_TOOLCHAIN_PATH/bin/arm-linux-gnueabihf-gcc"
	export CXX="$ARM_TOOLCHAIN_PATH/bin/arm-linux-gnueabihf-g++"
	export RANLIB="$ARM_TOOLCHAIN_PATH/bin/arm-linux-gnueabihf-ranlib"
	export AR="$ARM_TOOLCHAIN_PATH/bin/arm-linux-gnueabihf-ar"
	export LD="$ARM_TOOLCHAIN_PATH/bin/arm-linux-gnueabihf-ld"
	export AS="$ARM_TOOLCHAIN_PATH/bin/arm-linux-gnueabihf-as"
	export STRIP="$ARM_TOOLCHAIN_PATH/bin/arm-linux-gnueabihf-strip"
	export NM="$ARM_TOOLCHAIN_PATH/bin/arm-linux-gnueabihf-nm"
	export OBJCOPY="$ARM_TOOLCHAIN_PATH/bin/arm-linux-gnueabihf-objcopy"
	export OBJDUMP="$ARM_TOOLCHAIN_PATH/bin/arm-linux-gnueabihf-objdump"

	export ADDITIONAL_INCLUDES="-I$ARM_TOOLCHAIN_PATH/arm-linux-gnueabihf/include -I$ARM_TOOLCHAIN_PATH/lib/gcc/arm-linux-gnueabihf/$ARM_GCC_VER/include -I$ARM_BOOST_PATH/include -I$INSTALL_ROOT/include"
	export ADDITIONAL_LIBRARIES="-L$ARM_TOOLCHAIN_PATH/arm-linux-gnueabihf/lib -L$ARM_TOOLCHAIN_PATH/lib -L$ARM_TOOLCHAIN_PATH/lib/gcc/arm-linux-gnueabihf/$ARM_GCC_VER/plugin -L$ARM_BOOST_PATH/lib -L$LIBRARIES_ROOT"

	export RPATHS="-Wl,-rpath,/opt/skale/lib -Wl,-rpath,/lib/arm-linux-gnueabihf"
	export CFLAGS="$ADDITIONAL_INCLUDES $ADDITIONAL_LIBRARIES $RPATHS -w $CFLAGS"
	export CXXFLAGS="$ADDITIONAL_INCLUDES $ADDITIONAL_LIBRARIES $RPATHS -w $CXXFLAGS"

	export CMAKE_CROSSCOMPILING_OPTS="-DCMAKE_POSITION_INDEPENDENT_CODE=ON CMAKE_C_COMPILER=$CC CMAKE_CXX_COMPILER=$CXX"

	export CONF_CROSSCOMPILING_OPTS_GENERIC="--host=arm-linux"
	export CONF_CROSSCOMPILING_OPTS_VORBIS="--host=arm-linux --target=$ARM_TOOLCHAIN_PATH/bin/$HELPER_ARM_TOOLCHAIN_NAME"
	export CONF_CROSSCOMPILING_OPTS_CURL="--host=$ARM_TOOLCHAIN_PATH/bin/$HELPER_ARM_TOOLCHAIN_NAME --target=armv7-linux-gcc"
	export CONF_CROSSCOMPILING_OPTS_BOOST="toolset=gcc-arm target-os=linux"
	export CONF_CROSSCOMPILING_OPTS_VPX="--target=armv7-linux-gcc --cpu=cortex-a7"
	export CONF_CROSSCOMPILING_OPTS_X264="--host=arm-linux --disable-asm --disable-opencl"
	export CONF_CROSSCOMPILING_OPTS_FFMPEG="--enable-cross-compile --cross-prefix=$ARM_TOOLCHAIN_PATH/bin/$HELPER_ARM_TOOLCHAIN_NAME- --arch=armel --target-os=linux --disable-asm"
	export UPNP_DISABLE_LARGE_FILE_SUPPORT="--disable-largefile"
fi

if [[ ! -z $SET_CC ]];
then
    CC=$SET_CC
fi
if [[ ! -z $SET_CXX ]];
then
    CXX=$SET_CXX
fi

if [ -z "${CC}" ];
then
	echo -e "${COLOR_ERROR}error: build requires gcc compiler or link which was not detected successfully${COLOR_RESET}"
	cd "$WORKING_DIR_OLD"
	env_restore_original
	exit 255
fi
if [ -z "${CXX}" ];
then
	echo -e "${COLOR_ERROR}error: build requires g++ compiler or link which was not detected successfully${COLOR_RESET}"
	cd "$WORKING_DIR_OLD"
	env_restore_original
	exit 255
fi
export CMAKE="$CMAKE -DUSE_LLVM=$USE_LLVM -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_LINKER=$LD -DCMAKE_AR=$AR -DCMAKE_OBJCOPY=$OBJCOPY -DCMAKE_OBJDUMP=$OBJDUMP -DCMAKE_RANLIB=$RANLIB -DCMAKE_NM=$NM"
#
echo -e "${COLOR_VAR_NAME}WORKING_DIR_OLD${COLOR_DOTS}........${COLOR_VAR_DESC}Started in directory${COLOR_DOTS}...................${COLOR_VAR_VAL}$WORKING_DIR_OLD${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WORKING_DIR_NEW${COLOR_DOTS}........${COLOR_VAR_DESC}Switched to directory${COLOR_DOTS}..................${COLOR_VAR_VAL}$WORKING_DIR_NEW${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}UNIX_SYSTEM_NAME${COLOR_DOTS}.......${COLOR_VAR_DESC}Building on host${COLOR_DOTS}.......................${COLOR_VAR_VAL}$UNIX_SYSTEM_NAME${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}NUMBER_OF_CPU_CORES${COLOR_DOTS}....${COLOR_VAR_DESC}Building on host having CPU cores${COLOR_DOTS}......${COLOR_VAR_VAL}$NUMBER_OF_CPU_CORES${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}ARCH${COLOR_DOTS}...................${COLOR_VAR_DESC}Building for architecture${COLOR_DOTS}..............${COLOR_VAR_VAL}$ARCH${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}DEBUG${COLOR_DOTS}.........................................................${COLOR_VAR_VAL}$DEBUG${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}TOP_CMAKE_BUILD_TYPE${COLOR_DOTS}...${COLOR_VAR_DESC}Building confiuration${COLOR_DOTS}..................${COLOR_VAR_VAL}$TOP_CMAKE_BUILD_TYPE${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}CUSTOM_BUILD_ROOT${COLOR_DOTS}......${COLOR_VAR_DESC}Building in directory${COLOR_DOTS}..................${COLOR_VAR_VAL}$CUSTOM_BUILD_ROOT${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}SOURCES_ROOT${COLOR_DOTS}...........${COLOR_VAR_DESC}Libraries source directory${COLOR_DOTS}.............${COLOR_VAR_VAL}$SOURCES_ROOT${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}PREDOWNLOADED_ROOT${COLOR_DOTS}.....${COLOR_VAR_DESC}Pre-downloaded directory${COLOR_DOTS}...............${COLOR_VAR_VAL}$PREDOWNLOADED_ROOT${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}INSTALL_ROOT${COLOR_DOTS}...........${COLOR_VAR_DESC}Install directory(prefix)${COLOR_DOTS}..............${COLOR_VAR_VAL}$INSTALL_ROOT${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}PARALLEL_COUNT${COLOR_DOTS}................................................${COLOR_VAR_VAL}$PARALLEL_COUNT${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}PARALLEL_MAKE_OPTIONS${COLOR_DOTS}.........................................${COLOR_VAR_VAL}$PARALLEL_MAKE_OPTIONS${COLOR_RESET}"
#echo -e "${COLOR_VAR_NAME}DYLD_LIBRARY_PATH${COLOR_DOTS}.............................................${COLOR_VAR_VAL}$DYLD_LIBRARY_PATH${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}USE_LLVM${COLOR_DOTS}......................................................${COLOR_VAR_VAL}$USE_LLVM${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}ADDITIONAL_INCLUDES${COLOR_DOTS}...........................................${COLOR_VAR_VAL}$ADDITIONAL_INCLUDES${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}ADDITIONAL_LIBRARIES${COLOR_DOTS}..........................................${COLOR_VAR_VAL}$ADDITIONAL_LIBRARIES${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}CFLAGS${COLOR_DOTS}........................................................${COLOR_VAR_VAL}$CFLAGS${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}CXXFLAGS${COLOR_DOTS}......................................................${COLOR_VAR_VAL}$CXXFLAGS${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}CC${COLOR_DOTS}............................................................${COLOR_VAR_VAL}$CC${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}CXX${COLOR_DOTS}...........................................................${COLOR_VAR_VAL}$CXX${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}MAKE${COLOR_DOTS}..........................................................${COLOR_VAR_VAL}$MAKE${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}CMAKE${COLOR_DOTS}.........................................................${COLOR_VAR_VAL}$CMAKE${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}CCMAKE${COLOR_DOTS}........................................................${COLOR_VAR_VAL}$CCMAKE${COLOR_RESET}"
#echo -e "${COLOR_VAR_NAME}SCONS${COLOR_DOTS}.........................................................${COLOR_VAR_VAL}$SCONS${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WGET${COLOR_DOTS}..........................................................${COLOR_VAR_VAL}$WGET${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}AUTOCONF${COLOR_DOTS}......................................................${COLOR_VAR_VAL}$AUTOCONF${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}AUTOGEN${COLOR_DOTS}.......................................................${COLOR_VAR_VAL}$AUTOGEN${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}AUTOMAKE${COLOR_DOTS}......................................................${COLOR_VAR_VAL}$AUTOMAKE${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}M4${COLOR_DOTS}............................................................${COLOR_VAR_VAL}$M4${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}LIBTOOL${COLOR_DOTS}.......................................................${COLOR_VAR_VAL}$LIBTOOL${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}SHTOOL${COLOR_DOTS}........................................................${COLOR_VAR_VAL}$SHTOOL${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}PKG_CONFIG${COLOR_DOTS}....................................................${COLOR_VAR_VAL}$PKG_CONFIG${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}SED${COLOR_DOTS}...........................................................${COLOR_VAR_VAL}$SED${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}AWK${COLOR_DOTS}...........................................................${COLOR_VAR_VAL}$AWK${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}YASM${COLOR_DOTS}..........................................................${COLOR_VAR_VAL}$YASM${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}NASM${COLOR_DOTS}..........................................................${COLOR_VAR_VAL}$NASM${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}AS${COLOR_DOTS}............................................................${COLOR_VAR_VAL}$AS${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}CC${COLOR_DOTS}............................................................${COLOR_VAR_VAL}$CC${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}CXX${COLOR_DOTS}...........................................................${COLOR_VAR_VAL}$CXX${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}AR${COLOR_DOTS}............................................................${COLOR_VAR_VAL}$AR${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}LD${COLOR_DOTS}............................................................${COLOR_VAR_VAL}$LD${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}STRIP${COLOR_DOTS}.........................................................${COLOR_VAR_VAL}$STRIP${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}RANLIB${COLOR_DOTS}........................................................${COLOR_VAR_VAL}$RANLIB${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}NM${COLOR_DOTS}............................................................${COLOR_VAR_VAL}$NM${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}OBJCOPY${COLOR_DOTS}.......................................................${COLOR_VAR_VAL}$OBJCOPY${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}OBJDUMP${COLOR_DOTS}.......................................................${COLOR_VAR_VAL}$OBJDUMP${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_ZLIB${COLOR_DOTS}..............${COLOR_VAR_DESC}Zlib${COLOR_DOTS}...................................${COLOR_VAR_VAL}$WITH_ZLIB${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_OPENSSL${COLOR_DOTS}...........${COLOR_VAR_DESC}OpenSSL${COLOR_DOTS}................................${COLOR_VAR_VAL}$WITH_OPENSSL${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_CURL${COLOR_DOTS}..............${COLOR_VAR_DESC}CURL${COLOR_DOTS}...................................${COLOR_VAR_VAL}$WITH_CURL${COLOR_RESET}"
#echo -e "${COLOR_VAR_NAME}WITH_LZMA${COLOR_DOTS}..............${COLOR_VAR_DESC}LZMA${COLOR_DOTS}...................................${COLOR_VAR_VAL}$WITH_LZMA${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_SSH${COLOR_DOTS}...............${COLOR_VAR_DESC}SSH${COLOR_DOTS}....................................${COLOR_VAR_VAL}$WITH_SSH${COLOR_RESET}"
#echo -e "${COLOR_VAR_NAME}WITH_SDL${COLOR_DOTS}...............${COLOR_VAR_DESC}SDL${COLOR_DOTS}....................................${COLOR_VAR_VAL}$WITH_SDL${COLOR_RESET}"
#echo -e "${COLOR_VAR_NAME}WITH_SDL_TTF${COLOR_DOTS}...........${COLOR_VAR_DESC}SDL-TTF${COLOR_DOTS}................................${COLOR_VAR_VAL}$WITH_SDL_TTF${COLOR_RESET}"
#echo -e "${COLOR_VAR_NAME}WITH_EV${COLOR_DOTS}................${COLOR_VAR_DESC}libEv${COLOR_DOTS}..................................${COLOR_VAR_VAL}$WITH_EV${COLOR_RESET}"
#echo -e "${COLOR_VAR_NAME}WITH_EVENT${COLOR_DOTS}.............${COLOR_VAR_DESC}libEvent${COLOR_DOTS}...............................${COLOR_VAR_VAL}$WITH_EVENT${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_UV${COLOR_DOTS}................${COLOR_VAR_DESC}libUV${COLOR_DOTS}..................................${COLOR_VAR_VAL}$WITH_UV${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_LWS${COLOR_DOTS}...............${COLOR_VAR_DESC}libWevSockets${COLOR_DOTS}..........................${COLOR_VAR_VAL}$WITH_LWS${COLOR_RESET}"
#echo -e "${COLOR_VAR_NAME}WITH_SOURCEY${COLOR_DOTS}...........${COLOR_VAR_DESC}libSourcey${COLOR_DOTS}.............................${COLOR_VAR_VAL}$WITH_SOURCEY${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_BOOST${COLOR_DOTS}.............${COLOR_VAR_DESC}libBoostC++${COLOR_DOTS}............................${COLOR_VAR_VAL}$WITH_BOOST${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_PUPNP${COLOR_DOTS}.............${COLOR_VAR_DESC}libpupnp${COLOR_DOTS}...............................${COLOR_VAR_VAL}$WITH_PUPNP${COLOR_RESET}"
#echo -e "${COLOR_VAR_NAME}WITH_GTEST${COLOR_DOTS}.............${COLOR_VAR_DESC}GTEST${COLOR_DOTS}..................................${COLOR_VAR_VAL}$WITH_GTEST${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_ARGTABLE2${COLOR_DOTS}.........${COLOR_VAR_DESC}libArgTable${COLOR_DOTS}............................${COLOR_VAR_VAL}$WITH_ARGTABLE2${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_NETTLE${COLOR_DOTS}............${COLOR_VAR_DESC}LibNettle${COLOR_DOTS}..............................${COLOR_VAR_VAL}$WITH_NETTLE${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_TASN1${COLOR_DOTS}.............${COLOR_VAR_DESC}libTASN1${COLOR_DOTS}...............................${COLOR_VAR_VAL}$WITH_TASN1${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_GNU_TLS${COLOR_DOTS}...........${COLOR_VAR_DESC}libGnuTLS${COLOR_DOTS}..............................${COLOR_VAR_VAL}$WITH_GNU_TLS${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_GPGERROR${COLOR_DOTS}..........${COLOR_VAR_DESC}libGpgError${COLOR_DOTS}............................${COLOR_VAR_VAL}$WITH_GPGERROR${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_GCRYPT${COLOR_DOTS}............${COLOR_VAR_DESC}libGCrypt${COLOR_DOTS}..............................${COLOR_VAR_VAL}$WITH_GCRYPT${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_MICRO_HTTP_D${COLOR_DOTS}......${COLOR_VAR_DESC}libMiniHttpD${COLOR_DOTS}...........................${COLOR_VAR_VAL}$WITH_MICRO_HTTP_D${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_JSONCPP${COLOR_DOTS}...........${COLOR_VAR_DESC}LibJsonC++${COLOR_DOTS}.............................${COLOR_VAR_VAL}$WITH_JSONCPP${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_JSONRPCCPP${COLOR_DOTS}........${COLOR_VAR_DESC}LibJsonRpcC++${COLOR_DOTS}..........................${COLOR_VAR_VAL}$WITH_JSONRPCCPP${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_CRYPTOPP${COLOR_DOTS}..........${COLOR_VAR_DESC}LibCrypto++${COLOR_DOTS}............................${COLOR_VAR_VAL}$WITH_CRYPTOPP${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_GMP${COLOR_DOTS}...............${COLOR_VAR_DESC}LibGMP${COLOR_DOTS}.................................${COLOR_VAR_VAL}$WITH_GMP${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_FF${COLOR_DOTS}................${COLOR_VAR_DESC}LibFF${COLOR_DOTS}..................................${COLOR_VAR_VAL}$WITH_FF${COLOR_RESET}"
echo -e "${COLOR_VAR_NAME}WITH_PBC${COLOR_DOTS}...............${COLOR_VAR_DESC}LibPBC${COLOR_DOTS}.................................${COLOR_VAR_VAL}$WITH_PBC${COLOR_RESET}"

#
#
#

cd "$SOURCES_ROOT"

env_save() {
	export > "$SOURCES_ROOT/saved_environment_pre_configured.txt"
}

env_restore() {
	if [ -f "${SOURCES_ROOT}/saved_environment_pre_configured.txt" ]; then
    	#echo "\"${SOURCES_ROOT}/saved_environment_pre_configured.txt\" exist, can restore env"
		#ENV_RESTORE_CMD="source \"${SOURCES_ROOT}/saved_environment_pre_configured.txt\""
		#env_clear_all
		#$ENV_RESTORE_CMD || true &> /dev/null
		source "${SOURCES_ROOT}/saved_environment_pre_configured.txt"
	fi
}

# we will save env now, next times we will only restore it)
env_save

if [ "$WITH_BOOST" = "yes" ];
then
	echo -e "${COLOR_SEPARATOR}==================== ${COLOR_PROJECT_NAME}BOOST${COLOR_SEPARATOR} ========================================${COLOR_RESET}"
	if [ ! -f "$INSTALL_ROOT/lib/libboost_system.a" ];
	then
		env_restore
		cd "$SOURCES_ROOT"
		if [ ! -d "boost_1_68_0" ];
		then
			if [ ! -f "boost_1_68_0.tar.bz2" ];
			then
				echo -e "${COLOR_INFO}downloading it${COLOR_DOTS}...${COLOR_RESET}"
                # $WGET https://dl.bintray.com/boostorg/release/1.68.0/source/boost_1_68_0.tar.gz
                $WGET  https://boostorg.jfrog.io/artifactory/main/release/1.68.0/source/boost_1_68_0.tar.bz2
			fi
			echo -e "${COLOR_INFO}unpacking it${COLOR_DOTS}...${COLOR_RESET}"
            tar -xf boost_1_68_0.tar.bz2
		fi
		cd boost_1_68_0
		echo -e "${COLOR_INFO}configuring and building it${COLOR_DOTS}...${COLOR_RESET}"

		./bootstrap.sh --prefix="$INSTALL_ROOT" --with-libraries=system,thread,filesystem,regex,atomic,program_options

	if [ ${ARCH} = "arm" ]
	then
		sed -i -e 's#using gcc ;#using gcc : arm : /usr/local/toolchains/gcc7.2-arm/bin/arm-linux-gnueabihf-g++ ;#g' project-config.jam
		./b2 "${CONF_CROSSCOMPILING_OPTS_BOOST}" cxxflags=-fPIC cflags=-fPIC ${PARALLEL_MAKE_OPTIONS} --prefix="$INSTALL_ROOT" --layout=system variant=debug link=static threading=multi install
		else
		./b2 cxxflags=-fPIC cxxstd=14 cflags=-fPIC ${PARALLEL_MAKE_OPTIONS} --prefix="$INSTALL_ROOT" --layout=system variant=debug link=static threading=multi install
	fi
		cd ..
		cd "$SOURCES_ROOT"
	else
		echo -e "${COLOR_SUCCESS}SKIPPED${COLOR_RESET}"
	fi
fi

if [ "$WITH_OPENSSL" = "yes" ];
then
	echo -e "${COLOR_SEPARATOR}==================== ${COLOR_PROJECT_NAME}Open SSL${COLOR_SEPARATOR} =====================================${COLOR_RESET}"
	if [ ! -f "$INSTALL_ROOT/lib/libssl.a" ];
	then
		## openssl
		## https://www.openssl.org/
		## https://wiki.openssl.org/index.php/Compilation_and_Installation
		## (required for libff)
		env_restore
		cd "$SOURCES_ROOT"
		if [ ! -d "openssl" ];
		then
			if [ ! -f "openssl-from-git.tar.gz" ];
			then
				echo -e "${COLOR_INFO}getting it from git${COLOR_DOTS}...${COLOR_RESET}"
				git clone https://github.com/openssl/openssl.git
				echo -e "${COLOR_INFO}archiving it${COLOR_DOTS}...${COLOR_RESET}"
				tar -czf openssl-from-git.tar.gz ./openssl
			else
				echo -e "${COLOR_INFO}unpacking it${COLOR_DOTS}...${COLOR_RESET}"
				tar -xzf openssl-from-git.tar.gz
			fi
			echo -e "${COLOR_INFO}configuring it${COLOR_DOTS}...${COLOR_RESET}"
			cd openssl
			git fetch
			git checkout OpenSSL_1_1_1-stable
			if [ "$ARCH" = "x86_or_x64" ];
			then
				if [ "$UNIX_SYSTEM_NAME" = "Darwin" ];
				then
					export KERNEL_BITS=64
					./Configure darwin64-x86_64-cc -fPIC no-shared --prefix="$INSTALL_ROOT"
				else
					./config -fPIC no-shared --prefix="$INSTALL_ROOT" --openssldir="$INSTALL_ROOT"
				fi
			else
				./Configure linux-armv4 --prefix="$INSTALL_ROOT" "${ADDITIONAL_INCLUDES}" "${ADDITIONAL_LIBRARIES}" no-shared no-tests no-dso
			fi
			cd ..
		fi
		echo -e "${COLOR_INFO}building it${COLOR_DOTS}...${COLOR_RESET}"
		cd openssl
		$MAKE ${PARALLEL_MAKE_OPTIONS} depend
		$MAKE ${PARALLEL_MAKE_OPTIONS}
		$MAKE ${PARALLEL_MAKE_OPTIONS} install_sw
		cd "$SOURCES_ROOT"
	else
		echo -e "${COLOR_SUCCESS}SKIPPED${COLOR_RESET}"
	fi
fi

if [ "$WITH_GMP" = "yes" ];
then
	echo -e "${COLOR_SEPARATOR}==================== ${COLOR_PROJECT_NAME}GMP${COLOR_SEPARATOR} ==========================================${COLOR_RESET}"
	if [ ! -f "$INSTALL_ROOT/lib/libgmp.a" ] || [ ! -f "$INSTALL_ROOT/lib/libgmpxx.a" ] || [ ! -f "$INSTALL_ROOT/lib/libgmp.la" ] || [ ! -f "$INSTALL_ROOT/lib/libgmpxx.la" ];
	then
		# requiired for libff and pbc
		env_restore
		cd "$SOURCES_ROOT"
		if [ ! -d "gmp-6.1.2" ];
		then
			if [ ! -f "gmp-6.1.2.tar.xz" ];
				then
			echo -e "${COLOR_INFO}getting it from gmp website${COLOR_DOTS}...${COLOR_RESET}"
			$WGET https://ftp.gnu.org/gnu/gmp/gmp-6.1.2.tar.xz
			fi
			echo -e "${COLOR_INFO}unpacking it${COLOR_DOTS}...${COLOR_RESET}"
			tar -xf gmp-6.1.2.tar.xz
		fi
		cd gmp-6.1.2
		echo -e "${COLOR_INFO}configuring it${COLOR_DOTS}...${COLOR_RESET}"
		./configure ${CONF_CROSSCOMPILING_OPTS_GENERIC} ${CONF_CROSSCOMPILING_OPTS_GMP} ${CONF_DEBUG_OPTIONS} --enable-cxx --enable-static --disable-shared --prefix="$INSTALL_ROOT"
		echo -e "${COLOR_INFO}building it${COLOR_DOTS}...${COLOR_RESET}"
		$MAKE ${PARALLEL_MAKE_OPTIONS}
		$MAKE ${PARALLEL_MAKE_OPTIONS} install
		cd ..
		cd "$SOURCES_ROOT"
	else
		echo -e "${COLOR_SUCCESS}SKIPPED${COLOR_RESET}"
	fi
fi

if [ "$WITH_FF" = "yes" ];
then
	echo -e "${COLOR_SEPARATOR}==================== ${COLOR_PROJECT_NAME}FF${COLOR_SEPARATOR} ===========================================${COLOR_RESET}"
	if [ ! -f "$INSTALL_ROOT/lib/libff.a" ];
	then
		env_restore
			cd "$SOURCES_ROOT"
			if [ ! -d "libff" ];
			then
				echo -e "${COLOR_INFO}getting it from git${COLOR_DOTS}...${COLOR_RESET}"
				git clone https://github.com/scipr-lab/libff.git --recursive # libff
			fi
		cd libff
		echo -e "${COLOR_INFO}configuring it${COLOR_DOTS}...${COLOR_RESET}"
		git fetch
		git checkout 03b719a7c81757071f99fc60be1f7f7694e51390
		mkdir -p build
		cd build
		$CMAKE "${CMAKE_CROSSCOMPILING_OPTS}" -DCMAKE_INSTALL_PREFIX="$INSTALL_ROOT" -DCMAKE_BUILD_TYPE="$TOP_CMAKE_BUILD_TYPE" .. -DWITH_PROCPS=OFF
		echo -e "${COLOR_INFO}building it${COLOR_DOTS}...${COLOR_RESET}"
			$MAKE ${PARALLEL_MAKE_OPTIONS}
			$MAKE ${PARALLEL_MAKE_OPTIONS} install
			cd "$SOURCES_ROOT"
	else
		echo -e "${COLOR_SUCCESS}SKIPPED${COLOR_RESET}"
	fi
fi

if [ "$WITH_PBC" = "yes" ];
then
	echo -e "${COLOR_SEPARATOR}==================== ${COLOR_PROJECT_NAME}PBC${COLOR_SEPARATOR} ==========================================${COLOR_RESET}"
	if [ ! -f "$INSTALL_ROOT/lib/libpbc.a" ] || [ ! -f "$INSTALL_ROOT/lib/libpbc.la" ];
	then
		env_restore
			cd "$SOURCES_ROOT"
			if [ ! -d "pbc" ];
			then
				echo -e "${COLOR_INFO}getting it from git${COLOR_DOTS}...${COLOR_RESET}"
				git clone https://github.com/skalenetwork/pbc.git # pbc
			fi
		echo -e "${COLOR_INFO}configuring it${COLOR_DOTS}...${COLOR_RESET}"
		cd pbc
		export CFLAGS="$CFLAGS -I${INSTALL_ROOT}/include"
		export CXXFLAGS="$CXXFLAGS -I${INSTALL_ROOT}/include"
		export CPPFLAGS="$CPPFLAGS -I${INSTALL_ROOT}/include"
		export LDFLAGS="$LDFLAGS -L${INSTALL_ROOT}/lib"
		echo "    CFLAGS   = $CFLAGS"
		echo "    CXXFLAGS = $CXXFLAGS"
		echo "    CPPFLAGS = $CPPFLAGS"
		echo "    LDFLAGS  = $LDFLAGS"
		$LIBTOOLIZE --force && aclocal && autoheader && automake --force-missing --add-missing && autoconf
		./configure ${CONF_CROSSCOMPILING_OPTS_GENERIC} ${CONF_DEBUG_OPTIONS} --with-pic --enable-static --disable-shared --prefix="$INSTALL_ROOT"
		echo -e "${COLOR_INFO}building it${COLOR_DOTS}...${COLOR_RESET}"
			$MAKE ${PARALLEL_MAKE_OPTIONS}
			$MAKE ${PARALLEL_MAKE_OPTIONS} install
			cd "$SOURCES_ROOT"
	else
		echo -e "${COLOR_SUCCESS}SKIPPED${COLOR_RESET}"
	fi
fi

echo -e "${COLOR_SEPARATOR}===================================================================${COLOR_RESET}"
echo -e "${COLOR_YELLOW}BLS dependencies build actions...${COLOR_RESET}"
echo -e "${COLOR_SEPARATOR}==================== ${COLOR_PROJECT_NAME}FINISH${COLOR_SEPARATOR} =======================================${COLOR_RESET}"
echo -e " "
echo -e " "
echo -e " "

#env_restore
#cd "$CUSTOM_BUILD_ROOT"
cd "$WORKING_DIR_OLD"
env_restore_original
exit 0
