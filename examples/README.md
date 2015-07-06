## Examples
This directory contains project with examples that shows how to use Virgil Security libraries
    can be used to solve specific tasks.

### General statements

1. Examples MUST be run from their directory.
1. All results are stored in the same directory.
1. To produce file `virgil_public.key` run:
    - `get_public_key` - if user is registered;
    - `register_user` - if user is not registered.
1. To produce `test.txt.sign` run `sign`.
1. To produce `text.txt.enc` run `encrypt`.
1. To produce `decrypted_text.txt` run `decrypt`.

## Build

### Build prerequisite:

1. [CMake](http://www.cmake.org/).
1. [Git](http://git-scm.com/).
1. [Python](http://python.org/).
1. [Python YAML](http://pyyaml.org/).
1. C/C++ compiler:
    * [gcc](https://gcc.gnu.org/)
    * [clang](http://clang.llvm.org/)
    * [MinGW](http://www.mingw.org/)
    * [Microsoft Visual Studio](http://www.visualstudio.com/), or other.
1. [libcurl](http://curl.haxx.se/libcurl/).

### Build steps:

1. `mkdir build`
1. `cd build`
1. `cmake ../examples`
1. `make`
