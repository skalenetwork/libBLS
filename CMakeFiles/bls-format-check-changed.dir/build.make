# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.21

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /snap/clion/180/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /snap/clion/180/bin/cmake/linux/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /d/skale-consensus

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /d/skale-consensus

# Utility rule file for bls-format-check-changed.

# Include any custom commands dependencies for this target.
include libBLS/CMakeFiles/bls-format-check-changed.dir/compiler_depend.make

# Include the progress variables for this target.
include libBLS/CMakeFiles/bls-format-check-changed.dir/progress.make

libBLS/CMakeFiles/bls-format-check-changed:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/d/skale-consensus/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Checking changed files in git"
	/d/skale-consensus/libBLS/cmake/../scripts/clang-format-check-changed.py --file-extensions ".cpp,*.cpp,*.h,*.cxx,*.hxx,*.hpp,*.cc,*.ipp" --exclude=/d/skale-consensus --exclude=/d/skale-consensus/libBLS/deps --exclude=/CMakeFiles/ --exclude=cmake --clang-format-bin /usr/bin/clang-format-6.0

bls-format-check-changed: libBLS/CMakeFiles/bls-format-check-changed
bls-format-check-changed: libBLS/CMakeFiles/bls-format-check-changed.dir/build.make
.PHONY : bls-format-check-changed

# Rule to build all files generated by this target.
libBLS/CMakeFiles/bls-format-check-changed.dir/build: bls-format-check-changed
.PHONY : libBLS/CMakeFiles/bls-format-check-changed.dir/build

libBLS/CMakeFiles/bls-format-check-changed.dir/clean:
	cd /d/skale-consensus/libBLS && $(CMAKE_COMMAND) -P CMakeFiles/bls-format-check-changed.dir/cmake_clean.cmake
.PHONY : libBLS/CMakeFiles/bls-format-check-changed.dir/clean

libBLS/CMakeFiles/bls-format-check-changed.dir/depend:
	cd /d/skale-consensus && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /d/skale-consensus /d/skale-consensus/libBLS /d/skale-consensus /d/skale-consensus/libBLS /d/skale-consensus/libBLS/CMakeFiles/bls-format-check-changed.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : libBLS/CMakeFiles/bls-format-check-changed.dir/depend

