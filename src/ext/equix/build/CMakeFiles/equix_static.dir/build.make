# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

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
CMAKE_SOURCE_DIR = /vagrant/tor/src/ext/equix

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /vagrant/tor/src/ext/equix/build

# Include any dependencies generated for this target.
include CMakeFiles/equix_static.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/equix_static.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/equix_static.dir/flags.make

CMakeFiles/equix_static.dir/src/context.c.o: CMakeFiles/equix_static.dir/flags.make
CMakeFiles/equix_static.dir/src/context.c.o: ../src/context.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/equix_static.dir/src/context.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/equix_static.dir/src/context.c.o   -c /vagrant/tor/src/ext/equix/src/context.c

CMakeFiles/equix_static.dir/src/context.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/equix_static.dir/src/context.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /vagrant/tor/src/ext/equix/src/context.c > CMakeFiles/equix_static.dir/src/context.c.i

CMakeFiles/equix_static.dir/src/context.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/equix_static.dir/src/context.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /vagrant/tor/src/ext/equix/src/context.c -o CMakeFiles/equix_static.dir/src/context.c.s

CMakeFiles/equix_static.dir/src/context.c.o.requires:

.PHONY : CMakeFiles/equix_static.dir/src/context.c.o.requires

CMakeFiles/equix_static.dir/src/context.c.o.provides: CMakeFiles/equix_static.dir/src/context.c.o.requires
	$(MAKE) -f CMakeFiles/equix_static.dir/build.make CMakeFiles/equix_static.dir/src/context.c.o.provides.build
.PHONY : CMakeFiles/equix_static.dir/src/context.c.o.provides

CMakeFiles/equix_static.dir/src/context.c.o.provides.build: CMakeFiles/equix_static.dir/src/context.c.o


CMakeFiles/equix_static.dir/src/equix.c.o: CMakeFiles/equix_static.dir/flags.make
CMakeFiles/equix_static.dir/src/equix.c.o: ../src/equix.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/equix_static.dir/src/equix.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/equix_static.dir/src/equix.c.o   -c /vagrant/tor/src/ext/equix/src/equix.c

CMakeFiles/equix_static.dir/src/equix.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/equix_static.dir/src/equix.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /vagrant/tor/src/ext/equix/src/equix.c > CMakeFiles/equix_static.dir/src/equix.c.i

CMakeFiles/equix_static.dir/src/equix.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/equix_static.dir/src/equix.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /vagrant/tor/src/ext/equix/src/equix.c -o CMakeFiles/equix_static.dir/src/equix.c.s

CMakeFiles/equix_static.dir/src/equix.c.o.requires:

.PHONY : CMakeFiles/equix_static.dir/src/equix.c.o.requires

CMakeFiles/equix_static.dir/src/equix.c.o.provides: CMakeFiles/equix_static.dir/src/equix.c.o.requires
	$(MAKE) -f CMakeFiles/equix_static.dir/build.make CMakeFiles/equix_static.dir/src/equix.c.o.provides.build
.PHONY : CMakeFiles/equix_static.dir/src/equix.c.o.provides

CMakeFiles/equix_static.dir/src/equix.c.o.provides.build: CMakeFiles/equix_static.dir/src/equix.c.o


CMakeFiles/equix_static.dir/src/solver.c.o: CMakeFiles/equix_static.dir/flags.make
CMakeFiles/equix_static.dir/src/solver.c.o: ../src/solver.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/equix_static.dir/src/solver.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/equix_static.dir/src/solver.c.o   -c /vagrant/tor/src/ext/equix/src/solver.c

CMakeFiles/equix_static.dir/src/solver.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/equix_static.dir/src/solver.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /vagrant/tor/src/ext/equix/src/solver.c > CMakeFiles/equix_static.dir/src/solver.c.i

CMakeFiles/equix_static.dir/src/solver.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/equix_static.dir/src/solver.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /vagrant/tor/src/ext/equix/src/solver.c -o CMakeFiles/equix_static.dir/src/solver.c.s

CMakeFiles/equix_static.dir/src/solver.c.o.requires:

.PHONY : CMakeFiles/equix_static.dir/src/solver.c.o.requires

CMakeFiles/equix_static.dir/src/solver.c.o.provides: CMakeFiles/equix_static.dir/src/solver.c.o.requires
	$(MAKE) -f CMakeFiles/equix_static.dir/build.make CMakeFiles/equix_static.dir/src/solver.c.o.provides.build
.PHONY : CMakeFiles/equix_static.dir/src/solver.c.o.provides

CMakeFiles/equix_static.dir/src/solver.c.o.provides.build: CMakeFiles/equix_static.dir/src/solver.c.o


# Object files for target equix_static
equix_static_OBJECTS = \
"CMakeFiles/equix_static.dir/src/context.c.o" \
"CMakeFiles/equix_static.dir/src/equix.c.o" \
"CMakeFiles/equix_static.dir/src/solver.c.o"

# External object files for target equix_static
equix_static_EXTERNAL_OBJECTS =

libequix.a: CMakeFiles/equix_static.dir/src/context.c.o
libequix.a: CMakeFiles/equix_static.dir/src/equix.c.o
libequix.a: CMakeFiles/equix_static.dir/src/solver.c.o
libequix.a: CMakeFiles/equix_static.dir/build.make
libequix.a: CMakeFiles/equix_static.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C static library libequix.a"
	$(CMAKE_COMMAND) -P CMakeFiles/equix_static.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/equix_static.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/equix_static.dir/build: libequix.a

.PHONY : CMakeFiles/equix_static.dir/build

CMakeFiles/equix_static.dir/requires: CMakeFiles/equix_static.dir/src/context.c.o.requires
CMakeFiles/equix_static.dir/requires: CMakeFiles/equix_static.dir/src/equix.c.o.requires
CMakeFiles/equix_static.dir/requires: CMakeFiles/equix_static.dir/src/solver.c.o.requires

.PHONY : CMakeFiles/equix_static.dir/requires

CMakeFiles/equix_static.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/equix_static.dir/cmake_clean.cmake
.PHONY : CMakeFiles/equix_static.dir/clean

CMakeFiles/equix_static.dir/depend:
	cd /vagrant/tor/src/ext/equix/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /vagrant/tor/src/ext/equix /vagrant/tor/src/ext/equix /vagrant/tor/src/ext/equix/build /vagrant/tor/src/ext/equix/build /vagrant/tor/src/ext/equix/build/CMakeFiles/equix_static.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/equix_static.dir/depend

