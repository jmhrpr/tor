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
include hashx/CMakeFiles/hashx.dir/depend.make

# Include the progress variables for this target.
include hashx/CMakeFiles/hashx.dir/progress.make

# Include the compile flags for this target's objects.
include hashx/CMakeFiles/hashx.dir/flags.make

hashx/CMakeFiles/hashx.dir/src/blake2.c.o: hashx/CMakeFiles/hashx.dir/flags.make
hashx/CMakeFiles/hashx.dir/src/blake2.c.o: ../hashx/src/blake2.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object hashx/CMakeFiles/hashx.dir/src/blake2.c.o"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hashx.dir/src/blake2.c.o   -c /vagrant/tor/src/ext/equix/hashx/src/blake2.c

hashx/CMakeFiles/hashx.dir/src/blake2.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hashx.dir/src/blake2.c.i"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /vagrant/tor/src/ext/equix/hashx/src/blake2.c > CMakeFiles/hashx.dir/src/blake2.c.i

hashx/CMakeFiles/hashx.dir/src/blake2.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hashx.dir/src/blake2.c.s"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /vagrant/tor/src/ext/equix/hashx/src/blake2.c -o CMakeFiles/hashx.dir/src/blake2.c.s

hashx/CMakeFiles/hashx.dir/src/blake2.c.o.requires:

.PHONY : hashx/CMakeFiles/hashx.dir/src/blake2.c.o.requires

hashx/CMakeFiles/hashx.dir/src/blake2.c.o.provides: hashx/CMakeFiles/hashx.dir/src/blake2.c.o.requires
	$(MAKE) -f hashx/CMakeFiles/hashx.dir/build.make hashx/CMakeFiles/hashx.dir/src/blake2.c.o.provides.build
.PHONY : hashx/CMakeFiles/hashx.dir/src/blake2.c.o.provides

hashx/CMakeFiles/hashx.dir/src/blake2.c.o.provides.build: hashx/CMakeFiles/hashx.dir/src/blake2.c.o


hashx/CMakeFiles/hashx.dir/src/compiler.c.o: hashx/CMakeFiles/hashx.dir/flags.make
hashx/CMakeFiles/hashx.dir/src/compiler.c.o: ../hashx/src/compiler.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object hashx/CMakeFiles/hashx.dir/src/compiler.c.o"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hashx.dir/src/compiler.c.o   -c /vagrant/tor/src/ext/equix/hashx/src/compiler.c

hashx/CMakeFiles/hashx.dir/src/compiler.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hashx.dir/src/compiler.c.i"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /vagrant/tor/src/ext/equix/hashx/src/compiler.c > CMakeFiles/hashx.dir/src/compiler.c.i

hashx/CMakeFiles/hashx.dir/src/compiler.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hashx.dir/src/compiler.c.s"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /vagrant/tor/src/ext/equix/hashx/src/compiler.c -o CMakeFiles/hashx.dir/src/compiler.c.s

hashx/CMakeFiles/hashx.dir/src/compiler.c.o.requires:

.PHONY : hashx/CMakeFiles/hashx.dir/src/compiler.c.o.requires

hashx/CMakeFiles/hashx.dir/src/compiler.c.o.provides: hashx/CMakeFiles/hashx.dir/src/compiler.c.o.requires
	$(MAKE) -f hashx/CMakeFiles/hashx.dir/build.make hashx/CMakeFiles/hashx.dir/src/compiler.c.o.provides.build
.PHONY : hashx/CMakeFiles/hashx.dir/src/compiler.c.o.provides

hashx/CMakeFiles/hashx.dir/src/compiler.c.o.provides.build: hashx/CMakeFiles/hashx.dir/src/compiler.c.o


hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.o: hashx/CMakeFiles/hashx.dir/flags.make
hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.o: ../hashx/src/compiler_a64.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.o"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hashx.dir/src/compiler_a64.c.o   -c /vagrant/tor/src/ext/equix/hashx/src/compiler_a64.c

hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hashx.dir/src/compiler_a64.c.i"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /vagrant/tor/src/ext/equix/hashx/src/compiler_a64.c > CMakeFiles/hashx.dir/src/compiler_a64.c.i

hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hashx.dir/src/compiler_a64.c.s"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /vagrant/tor/src/ext/equix/hashx/src/compiler_a64.c -o CMakeFiles/hashx.dir/src/compiler_a64.c.s

hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.o.requires:

.PHONY : hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.o.requires

hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.o.provides: hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.o.requires
	$(MAKE) -f hashx/CMakeFiles/hashx.dir/build.make hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.o.provides.build
.PHONY : hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.o.provides

hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.o.provides.build: hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.o


hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.o: hashx/CMakeFiles/hashx.dir/flags.make
hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.o: ../hashx/src/compiler_x86.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.o"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hashx.dir/src/compiler_x86.c.o   -c /vagrant/tor/src/ext/equix/hashx/src/compiler_x86.c

hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hashx.dir/src/compiler_x86.c.i"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /vagrant/tor/src/ext/equix/hashx/src/compiler_x86.c > CMakeFiles/hashx.dir/src/compiler_x86.c.i

hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hashx.dir/src/compiler_x86.c.s"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /vagrant/tor/src/ext/equix/hashx/src/compiler_x86.c -o CMakeFiles/hashx.dir/src/compiler_x86.c.s

hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.o.requires:

.PHONY : hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.o.requires

hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.o.provides: hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.o.requires
	$(MAKE) -f hashx/CMakeFiles/hashx.dir/build.make hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.o.provides.build
.PHONY : hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.o.provides

hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.o.provides.build: hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.o


hashx/CMakeFiles/hashx.dir/src/context.c.o: hashx/CMakeFiles/hashx.dir/flags.make
hashx/CMakeFiles/hashx.dir/src/context.c.o: ../hashx/src/context.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object hashx/CMakeFiles/hashx.dir/src/context.c.o"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hashx.dir/src/context.c.o   -c /vagrant/tor/src/ext/equix/hashx/src/context.c

hashx/CMakeFiles/hashx.dir/src/context.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hashx.dir/src/context.c.i"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /vagrant/tor/src/ext/equix/hashx/src/context.c > CMakeFiles/hashx.dir/src/context.c.i

hashx/CMakeFiles/hashx.dir/src/context.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hashx.dir/src/context.c.s"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /vagrant/tor/src/ext/equix/hashx/src/context.c -o CMakeFiles/hashx.dir/src/context.c.s

hashx/CMakeFiles/hashx.dir/src/context.c.o.requires:

.PHONY : hashx/CMakeFiles/hashx.dir/src/context.c.o.requires

hashx/CMakeFiles/hashx.dir/src/context.c.o.provides: hashx/CMakeFiles/hashx.dir/src/context.c.o.requires
	$(MAKE) -f hashx/CMakeFiles/hashx.dir/build.make hashx/CMakeFiles/hashx.dir/src/context.c.o.provides.build
.PHONY : hashx/CMakeFiles/hashx.dir/src/context.c.o.provides

hashx/CMakeFiles/hashx.dir/src/context.c.o.provides.build: hashx/CMakeFiles/hashx.dir/src/context.c.o


hashx/CMakeFiles/hashx.dir/src/hashx.c.o: hashx/CMakeFiles/hashx.dir/flags.make
hashx/CMakeFiles/hashx.dir/src/hashx.c.o: ../hashx/src/hashx.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object hashx/CMakeFiles/hashx.dir/src/hashx.c.o"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hashx.dir/src/hashx.c.o   -c /vagrant/tor/src/ext/equix/hashx/src/hashx.c

hashx/CMakeFiles/hashx.dir/src/hashx.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hashx.dir/src/hashx.c.i"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /vagrant/tor/src/ext/equix/hashx/src/hashx.c > CMakeFiles/hashx.dir/src/hashx.c.i

hashx/CMakeFiles/hashx.dir/src/hashx.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hashx.dir/src/hashx.c.s"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /vagrant/tor/src/ext/equix/hashx/src/hashx.c -o CMakeFiles/hashx.dir/src/hashx.c.s

hashx/CMakeFiles/hashx.dir/src/hashx.c.o.requires:

.PHONY : hashx/CMakeFiles/hashx.dir/src/hashx.c.o.requires

hashx/CMakeFiles/hashx.dir/src/hashx.c.o.provides: hashx/CMakeFiles/hashx.dir/src/hashx.c.o.requires
	$(MAKE) -f hashx/CMakeFiles/hashx.dir/build.make hashx/CMakeFiles/hashx.dir/src/hashx.c.o.provides.build
.PHONY : hashx/CMakeFiles/hashx.dir/src/hashx.c.o.provides

hashx/CMakeFiles/hashx.dir/src/hashx.c.o.provides.build: hashx/CMakeFiles/hashx.dir/src/hashx.c.o


hashx/CMakeFiles/hashx.dir/src/program.c.o: hashx/CMakeFiles/hashx.dir/flags.make
hashx/CMakeFiles/hashx.dir/src/program.c.o: ../hashx/src/program.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object hashx/CMakeFiles/hashx.dir/src/program.c.o"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hashx.dir/src/program.c.o   -c /vagrant/tor/src/ext/equix/hashx/src/program.c

hashx/CMakeFiles/hashx.dir/src/program.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hashx.dir/src/program.c.i"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /vagrant/tor/src/ext/equix/hashx/src/program.c > CMakeFiles/hashx.dir/src/program.c.i

hashx/CMakeFiles/hashx.dir/src/program.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hashx.dir/src/program.c.s"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /vagrant/tor/src/ext/equix/hashx/src/program.c -o CMakeFiles/hashx.dir/src/program.c.s

hashx/CMakeFiles/hashx.dir/src/program.c.o.requires:

.PHONY : hashx/CMakeFiles/hashx.dir/src/program.c.o.requires

hashx/CMakeFiles/hashx.dir/src/program.c.o.provides: hashx/CMakeFiles/hashx.dir/src/program.c.o.requires
	$(MAKE) -f hashx/CMakeFiles/hashx.dir/build.make hashx/CMakeFiles/hashx.dir/src/program.c.o.provides.build
.PHONY : hashx/CMakeFiles/hashx.dir/src/program.c.o.provides

hashx/CMakeFiles/hashx.dir/src/program.c.o.provides.build: hashx/CMakeFiles/hashx.dir/src/program.c.o


hashx/CMakeFiles/hashx.dir/src/program_exec.c.o: hashx/CMakeFiles/hashx.dir/flags.make
hashx/CMakeFiles/hashx.dir/src/program_exec.c.o: ../hashx/src/program_exec.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building C object hashx/CMakeFiles/hashx.dir/src/program_exec.c.o"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hashx.dir/src/program_exec.c.o   -c /vagrant/tor/src/ext/equix/hashx/src/program_exec.c

hashx/CMakeFiles/hashx.dir/src/program_exec.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hashx.dir/src/program_exec.c.i"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /vagrant/tor/src/ext/equix/hashx/src/program_exec.c > CMakeFiles/hashx.dir/src/program_exec.c.i

hashx/CMakeFiles/hashx.dir/src/program_exec.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hashx.dir/src/program_exec.c.s"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /vagrant/tor/src/ext/equix/hashx/src/program_exec.c -o CMakeFiles/hashx.dir/src/program_exec.c.s

hashx/CMakeFiles/hashx.dir/src/program_exec.c.o.requires:

.PHONY : hashx/CMakeFiles/hashx.dir/src/program_exec.c.o.requires

hashx/CMakeFiles/hashx.dir/src/program_exec.c.o.provides: hashx/CMakeFiles/hashx.dir/src/program_exec.c.o.requires
	$(MAKE) -f hashx/CMakeFiles/hashx.dir/build.make hashx/CMakeFiles/hashx.dir/src/program_exec.c.o.provides.build
.PHONY : hashx/CMakeFiles/hashx.dir/src/program_exec.c.o.provides

hashx/CMakeFiles/hashx.dir/src/program_exec.c.o.provides.build: hashx/CMakeFiles/hashx.dir/src/program_exec.c.o


hashx/CMakeFiles/hashx.dir/src/siphash.c.o: hashx/CMakeFiles/hashx.dir/flags.make
hashx/CMakeFiles/hashx.dir/src/siphash.c.o: ../hashx/src/siphash.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building C object hashx/CMakeFiles/hashx.dir/src/siphash.c.o"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hashx.dir/src/siphash.c.o   -c /vagrant/tor/src/ext/equix/hashx/src/siphash.c

hashx/CMakeFiles/hashx.dir/src/siphash.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hashx.dir/src/siphash.c.i"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /vagrant/tor/src/ext/equix/hashx/src/siphash.c > CMakeFiles/hashx.dir/src/siphash.c.i

hashx/CMakeFiles/hashx.dir/src/siphash.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hashx.dir/src/siphash.c.s"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /vagrant/tor/src/ext/equix/hashx/src/siphash.c -o CMakeFiles/hashx.dir/src/siphash.c.s

hashx/CMakeFiles/hashx.dir/src/siphash.c.o.requires:

.PHONY : hashx/CMakeFiles/hashx.dir/src/siphash.c.o.requires

hashx/CMakeFiles/hashx.dir/src/siphash.c.o.provides: hashx/CMakeFiles/hashx.dir/src/siphash.c.o.requires
	$(MAKE) -f hashx/CMakeFiles/hashx.dir/build.make hashx/CMakeFiles/hashx.dir/src/siphash.c.o.provides.build
.PHONY : hashx/CMakeFiles/hashx.dir/src/siphash.c.o.provides

hashx/CMakeFiles/hashx.dir/src/siphash.c.o.provides.build: hashx/CMakeFiles/hashx.dir/src/siphash.c.o


hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.o: hashx/CMakeFiles/hashx.dir/flags.make
hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.o: ../hashx/src/siphash_rng.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building C object hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.o"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hashx.dir/src/siphash_rng.c.o   -c /vagrant/tor/src/ext/equix/hashx/src/siphash_rng.c

hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hashx.dir/src/siphash_rng.c.i"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /vagrant/tor/src/ext/equix/hashx/src/siphash_rng.c > CMakeFiles/hashx.dir/src/siphash_rng.c.i

hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hashx.dir/src/siphash_rng.c.s"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /vagrant/tor/src/ext/equix/hashx/src/siphash_rng.c -o CMakeFiles/hashx.dir/src/siphash_rng.c.s

hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.o.requires:

.PHONY : hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.o.requires

hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.o.provides: hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.o.requires
	$(MAKE) -f hashx/CMakeFiles/hashx.dir/build.make hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.o.provides.build
.PHONY : hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.o.provides

hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.o.provides.build: hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.o


hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.o: hashx/CMakeFiles/hashx.dir/flags.make
hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.o: ../hashx/src/virtual_memory.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Building C object hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.o"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hashx.dir/src/virtual_memory.c.o   -c /vagrant/tor/src/ext/equix/hashx/src/virtual_memory.c

hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hashx.dir/src/virtual_memory.c.i"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /vagrant/tor/src/ext/equix/hashx/src/virtual_memory.c > CMakeFiles/hashx.dir/src/virtual_memory.c.i

hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hashx.dir/src/virtual_memory.c.s"
	cd /vagrant/tor/src/ext/equix/build/hashx && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /vagrant/tor/src/ext/equix/hashx/src/virtual_memory.c -o CMakeFiles/hashx.dir/src/virtual_memory.c.s

hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.o.requires:

.PHONY : hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.o.requires

hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.o.provides: hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.o.requires
	$(MAKE) -f hashx/CMakeFiles/hashx.dir/build.make hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.o.provides.build
.PHONY : hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.o.provides

hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.o.provides.build: hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.o


# Object files for target hashx
hashx_OBJECTS = \
"CMakeFiles/hashx.dir/src/blake2.c.o" \
"CMakeFiles/hashx.dir/src/compiler.c.o" \
"CMakeFiles/hashx.dir/src/compiler_a64.c.o" \
"CMakeFiles/hashx.dir/src/compiler_x86.c.o" \
"CMakeFiles/hashx.dir/src/context.c.o" \
"CMakeFiles/hashx.dir/src/hashx.c.o" \
"CMakeFiles/hashx.dir/src/program.c.o" \
"CMakeFiles/hashx.dir/src/program_exec.c.o" \
"CMakeFiles/hashx.dir/src/siphash.c.o" \
"CMakeFiles/hashx.dir/src/siphash_rng.c.o" \
"CMakeFiles/hashx.dir/src/virtual_memory.c.o"

# External object files for target hashx
hashx_EXTERNAL_OBJECTS =

hashx/libhashx.so.1.0.0: hashx/CMakeFiles/hashx.dir/src/blake2.c.o
hashx/libhashx.so.1.0.0: hashx/CMakeFiles/hashx.dir/src/compiler.c.o
hashx/libhashx.so.1.0.0: hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.o
hashx/libhashx.so.1.0.0: hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.o
hashx/libhashx.so.1.0.0: hashx/CMakeFiles/hashx.dir/src/context.c.o
hashx/libhashx.so.1.0.0: hashx/CMakeFiles/hashx.dir/src/hashx.c.o
hashx/libhashx.so.1.0.0: hashx/CMakeFiles/hashx.dir/src/program.c.o
hashx/libhashx.so.1.0.0: hashx/CMakeFiles/hashx.dir/src/program_exec.c.o
hashx/libhashx.so.1.0.0: hashx/CMakeFiles/hashx.dir/src/siphash.c.o
hashx/libhashx.so.1.0.0: hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.o
hashx/libhashx.so.1.0.0: hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.o
hashx/libhashx.so.1.0.0: hashx/CMakeFiles/hashx.dir/build.make
hashx/libhashx.so.1.0.0: hashx/CMakeFiles/hashx.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/vagrant/tor/src/ext/equix/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_12) "Linking C shared library libhashx.so"
	cd /vagrant/tor/src/ext/equix/build/hashx && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/hashx.dir/link.txt --verbose=$(VERBOSE)
	cd /vagrant/tor/src/ext/equix/build/hashx && $(CMAKE_COMMAND) -E cmake_symlink_library libhashx.so.1.0.0 libhashx.so.1 libhashx.so

hashx/libhashx.so.1: hashx/libhashx.so.1.0.0
	@$(CMAKE_COMMAND) -E touch_nocreate hashx/libhashx.so.1

hashx/libhashx.so: hashx/libhashx.so.1.0.0
	@$(CMAKE_COMMAND) -E touch_nocreate hashx/libhashx.so

# Rule to build all files generated by this target.
hashx/CMakeFiles/hashx.dir/build: hashx/libhashx.so

.PHONY : hashx/CMakeFiles/hashx.dir/build

hashx/CMakeFiles/hashx.dir/requires: hashx/CMakeFiles/hashx.dir/src/blake2.c.o.requires
hashx/CMakeFiles/hashx.dir/requires: hashx/CMakeFiles/hashx.dir/src/compiler.c.o.requires
hashx/CMakeFiles/hashx.dir/requires: hashx/CMakeFiles/hashx.dir/src/compiler_a64.c.o.requires
hashx/CMakeFiles/hashx.dir/requires: hashx/CMakeFiles/hashx.dir/src/compiler_x86.c.o.requires
hashx/CMakeFiles/hashx.dir/requires: hashx/CMakeFiles/hashx.dir/src/context.c.o.requires
hashx/CMakeFiles/hashx.dir/requires: hashx/CMakeFiles/hashx.dir/src/hashx.c.o.requires
hashx/CMakeFiles/hashx.dir/requires: hashx/CMakeFiles/hashx.dir/src/program.c.o.requires
hashx/CMakeFiles/hashx.dir/requires: hashx/CMakeFiles/hashx.dir/src/program_exec.c.o.requires
hashx/CMakeFiles/hashx.dir/requires: hashx/CMakeFiles/hashx.dir/src/siphash.c.o.requires
hashx/CMakeFiles/hashx.dir/requires: hashx/CMakeFiles/hashx.dir/src/siphash_rng.c.o.requires
hashx/CMakeFiles/hashx.dir/requires: hashx/CMakeFiles/hashx.dir/src/virtual_memory.c.o.requires

.PHONY : hashx/CMakeFiles/hashx.dir/requires

hashx/CMakeFiles/hashx.dir/clean:
	cd /vagrant/tor/src/ext/equix/build/hashx && $(CMAKE_COMMAND) -P CMakeFiles/hashx.dir/cmake_clean.cmake
.PHONY : hashx/CMakeFiles/hashx.dir/clean

hashx/CMakeFiles/hashx.dir/depend:
	cd /vagrant/tor/src/ext/equix/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /vagrant/tor/src/ext/equix /vagrant/tor/src/ext/equix/hashx /vagrant/tor/src/ext/equix/build /vagrant/tor/src/ext/equix/build/hashx /vagrant/tor/src/ext/equix/build/hashx/CMakeFiles/hashx.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : hashx/CMakeFiles/hashx.dir/depend

