# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.13

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/romerion/Git/ml-ethereum-client/libs/secp256k1/src

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/romerion/Git/ml-ethereum-client/libs/secp256k1/src

# Include any dependencies generated for this target.
include CMakeFiles/secp256k1.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/secp256k1.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/secp256k1.dir/flags.make

CMakeFiles/secp256k1.dir/secp256k1.o: CMakeFiles/secp256k1.dir/flags.make
CMakeFiles/secp256k1.dir/secp256k1.o: secp256k1.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/romerion/Git/ml-ethereum-client/libs/secp256k1/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/secp256k1.dir/secp256k1.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/secp256k1.dir/secp256k1.o   -c /home/romerion/Git/ml-ethereum-client/libs/secp256k1/src/secp256k1.c

CMakeFiles/secp256k1.dir/secp256k1.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/secp256k1.dir/secp256k1.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/romerion/Git/ml-ethereum-client/libs/secp256k1/src/secp256k1.c > CMakeFiles/secp256k1.dir/secp256k1.i

CMakeFiles/secp256k1.dir/secp256k1.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/secp256k1.dir/secp256k1.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/romerion/Git/ml-ethereum-client/libs/secp256k1/src/secp256k1.c -o CMakeFiles/secp256k1.dir/secp256k1.s

# Object files for target secp256k1
secp256k1_OBJECTS = \
"CMakeFiles/secp256k1.dir/secp256k1.o"

# External object files for target secp256k1
secp256k1_EXTERNAL_OBJECTS =

libsecp256k1.so: CMakeFiles/secp256k1.dir/secp256k1.o
libsecp256k1.so: CMakeFiles/secp256k1.dir/build.make
libsecp256k1.so: CMakeFiles/secp256k1.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/romerion/Git/ml-ethereum-client/libs/secp256k1/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C shared library libsecp256k1.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/secp256k1.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/secp256k1.dir/build: libsecp256k1.so

.PHONY : CMakeFiles/secp256k1.dir/build

CMakeFiles/secp256k1.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/secp256k1.dir/cmake_clean.cmake
.PHONY : CMakeFiles/secp256k1.dir/clean

CMakeFiles/secp256k1.dir/depend:
	cd /home/romerion/Git/ml-ethereum-client/libs/secp256k1/src && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/romerion/Git/ml-ethereum-client/libs/secp256k1/src /home/romerion/Git/ml-ethereum-client/libs/secp256k1/src /home/romerion/Git/ml-ethereum-client/libs/secp256k1/src /home/romerion/Git/ml-ethereum-client/libs/secp256k1/src /home/romerion/Git/ml-ethereum-client/libs/secp256k1/src/CMakeFiles/secp256k1.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/secp256k1.dir/depend
