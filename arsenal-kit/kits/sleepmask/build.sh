#!/usr/bin/env bash

# make our output look nice...
kit_name="Sleepmask kit"
USE_SYSCALLS=0
SYSCALLS_FILE="SYSCALLS_none"

function print_good () {
   echo -e "[${kit_name}] \x1B[01;32m[+]\x1B[0m $1"
}

function print_error () {
   echo -e "[${kit_name}] \x1B[01;31m[-]\x1B[0m $1"
}

function print_warning () {
   echo -e "[${kit_name}] \x1B[01;33m[-]\x1B[0m $1"
}

function print_info () {
   echo -e "[${kit_name}] \x1B[01;34m[*]\x1B[0m $1"
}

#
# Compile Sleep Mask for an X64 object
#
function compile_sleepmask64() {

   # compile our 64-bit object files

   print_info "Compile sleepmask.x64.o"
   ${CCx64}-gcc -m64 -c $options -DUSE_${sleep_method} -DUSE_SYSCALLS=${USE_SYSCALLS} -D${SYSCALLS_FILE} src/sleepmask.c -Wall -o "${1}/sleepmask.x64.o"

   print_info "Compile sleepmask_pivot.x64.o"
   ${CCx64}-gcc -m64 -c $options -DUSE_SYSCALLS=${USE_SYSCALLS} -D${SYSCALLS_FILE} src/sleepmask_pivot.c -Wall -o "${1}/sleepmask_pivot.x64.o"
}

function compile_sleepmask() {

   # compile our 32-bit object files
   print_info "Compile sleepmask.x86.o"
   ${CCx86}-gcc -c $options -DUSE_${sleep_method} -DUSE_SYSCALLS=${USE_SYSCALLS} -D${SYSCALLS_FILE} src/sleepmask.c -Wall -o "${1}/sleepmask.x86.o"

   print_info "Compile sleepmask_pivot.x86.o"
   ${CCx86}-gcc -c $options -DUSE_SYSCALLS=${USE_SYSCALLS} -D${SYSCALLS_FILE} src/sleepmask_pivot.c -Wall -o "${1}/sleepmask_pivot.x86.o"
}


# compiler flags to pass to all builds. Use this to set optimization level or tweak other fun things.
# -Os              - Optimize for size.
# -fno-jump-tables - Do not use jump tables
# -DDEBUG          - Turns on debug logging
#                    WARNING: Do not add DLOG/DLOGT statements into the 'syscalls' files, it will cause a crash
options="-Os -fno-jump-tables"

# change up the compiler if you need to
CCx86="i686-w64-mingw32"
CCx64="x86_64-w64-mingw32"

# check for a cross-compiler
if [ $(command -v ${CCx64}-gcc) ]; then
   print_good "You have a x86_64 mingw--I will recompile the sleepmask beacon object files"
else
   print_error "No cross-compiler detected. Try: apt-get install mingw-w64"
   exit 2
fi


#
# compile the sleep mask object files
#

if [[ $# -ne 3 ]]; then
   print_error "Missing parameters"
   print_error "Usage:"
   print_error "./build.sh <sleep_method> <syscalls> <output directory>"
   print_error " - Sleep Method     - Choose which function to use for sleeping"
   print_error "                        Valid options are: Sleep, WaitForSingleObject"
   print_error " - Syscalls         - set the system call method"
   print_error "                      Valid values [none embedded indirect indirect_randomized, beacon]"
   print_error " - Output Directory - Destination directory to save the output"
   print_error "Example:"
   print_error "./build.sh WaitForSingleObject indirect /tmp/dist/sleepmask"

   exit 2
fi

# Clean

sleep_method="${1}"
syscalls="${2}"
dist_directory="${3}"
support_syscall_beacon="false"

print_info "Building sleepmask to support Cobalt Strike"

# Check if the sleep method is valid.
valid_values="Sleep WaitForSingleObject"
if [[ ! $valid_values =~ (^|[[:space:]])"${sleep_method}"($|[[:space:]]) ]] ; then
   print_error "Invalid Sleep Method value: ${sleep_method}"
   print_error "Valid values are: ${valid_values}"
   exit 2
fi
print_info "Using Sleep Method: ${sleep_method}"

# Check if the syscalls is valid.
valid_values="none embedded indirect indirect_randomized beacon"
if [[ ! $valid_values =~ (^|[[:space:]])"${syscalls}"($|[[:space:]]) ]] ; then
   print_error "Invalid system call method: ${syscalls}"
   print_error "Valid values are: ${valid_values}"
   exit 2
fi

# Setup variables for the system call method
if [[ ${syscalls} != "none" ]] ; then
   USE_SYSCALLS=1
   SYSCALLS_FILE="SYSCALLS_${syscalls}"

   # -masm=intel - Added to support system calls.
   options="${options} -masm=intel"
fi
print_info "Using system call method: ${syscalls}"

rm -rf "${dist_directory}"
mkdir -p "${dist_directory}"

compile_sleepmask "${dist_directory}"
compile_sleepmask64 "${dist_directory}"

sed 's/KITNAME/sleepmask_kit/' ../../templates/helper_functions.template > "${dist_directory}/sleepmask.cna"
cat ./script_template.cna >> "${dist_directory}/sleepmask.cna"

print_good "The sleepmask beacon object files are saved in '${dist_directory}'"
