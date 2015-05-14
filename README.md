# Virgil Security C++ library

- [Introduction](#introduction)
- [Build prerequisite](#build-prerequisite)
- [Build](#build)
- [Examples](#examples)
    - [General statements](#general-statements)
    - [Example 1: Register user on the PKI service](#example-1-register-user-on-the-pki-service)
    - [Example 2: Encrypt data](#example-2-encrypt-data)
    - [Example 3: Decrypt data](#example-3-decrypt-data)
    - [Example 4: Sign data](#example-4-sign-data)
    - [Example 5: Verify data](#example-5-verify-data)
- [License](#license)
- [Contacts](#contacts)

## Introduction

This branch focuses on the C++ library implementation and covers next topics:

  * build prerequisite;
  * build;
  * usage exmaples.

Common library description can be found [here](https://github.com/VirgilSecurity/virgil).

## Build prerequisite

1. [CMake](http://www.cmake.org/).
1. [Git](http://git-scm.com/).
1. [Python](http://python.org/).
1. [Python YAML](http://pyyaml.org/).
1. C/C++ compiler:
    [gcc](https://gcc.gnu.org/),
    [clang](http://clang.llvm.org/),
    [MinGW](http://www.mingw.org/),
    [Microsoft Visual Studio](http://www.visualstudio.com/), or other.
1. [libcurl](http://curl.haxx.se/libcurl/).

## Build

1. Run one of the folowing scripts:

    * build.sh - on the Unix-like OS;
    * build.bat - on the Windows OS [coming soon].

1. Inspect folder `origin_lib` that contains built library.

1. Inspect folder `examples_bin` that contains built examples.

## Examples

This section describes common case library usage scenarios, like

  * encrypt data for user identified by email, phone, etc;
  * sign data with own private key;
  * verify data received via email, file sharing service, etc;
  * decrypt data if verification successful.

### General statements

1. Examples MUST be run from their directory.
1. All results are stored in the same directory.

### Example 1: Register user on the PKI service

*Input*: User ID

*Output*: Generated Keys, Registration status

```
EXAMPLE CODE [COMING SOON]
```

### Example 2: Encrypt data

*Input*: User ID, Data

*Output*: Encrypted data

```
EXAMPLE CODE [COMING SOON]
```

### Example 3: Decrypt data

*Input*: Encrypted data, Private Key, [Private Key password]

*Output*: Decrypted data

```
EXAMPLE CODE [COMING SOON]
```

### Example 4: Sign data

*Input*: Data, Extended Public Key, Private Key

*Output*: Sign

``` {.cpp}
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>
#include <stdexcept>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;
#include <virgil/service/VirgilStreamSigner.h>
using virgil::service::VirgilStreamSigner;
#include <virgil/stream/VirgilStreamDataSource.h>
using virgil::stream::VirgilStreamDataSource;
#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;
#include <virgil/stream/utils.h>

int main() {
    try {
        std::cout << "Prepare input file: test.txt..." << std::endl;
        std::ifstream inFile("test.txt", std::ios::in | std::ios::binary);
        if (!inFile.good()) {
            throw std::invalid_argument("can not read file: test.txt");
        }

        std::cout << "Prepare output file: test.txt.sign..." << std::endl;
        std::ofstream outFile("test.txt.sign", std::ios::out | std::ios::binary);
        if (!outFile.good()) {
            throw std::invalid_argument("can not write file: test.txt.sign");
        }

        std::cout << "Read extended public key..." << std::endl;
        VirgilCertificate certificate = virgil::stream::read_certificate("public.key");

        std::cout << "Read private key..." << std::endl;
        std::ifstream keyFile("private.key", std::ios::in | std::ios::binary);
        if (!keyFile.good()) {
            throw std::invalid_argument("can not read private key: private.key");
        }
        VirgilByteArray privateKey;
        std::copy(std::istreambuf_iterator<char>(keyFile), std::istreambuf_iterator<char>(),
                std::back_inserter(privateKey));
        VirgilByteArray privateKeyPassword = virgil::str2bytes("password");

        std::cout << "Initialize signer..." << std::endl;
        VirgilStreamSigner signer;

        std::cout << "Sign data..." << std::endl;
        VirgilStreamDataSource dataSource(inFile);
        VirgilSign sign = signer.sign(dataSource, certificate.id().certificateId(),
                privateKey, privateKeyPassword);

        std::cout << "Save sign..." << std::endl;
        VirgilByteArray signData = sign.toAsn1();
        std::copy(signData.begin(), signData.end(), std::ostreambuf_iterator<char>(outFile));
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
    }
    std::cout << "Sign is successfully stored in the output file." << std::endl;
    return 0;
}
```

### Example 5: Verify data

*Input*: Signer Id, Data, Sign

*Output*: Verification result

```
EXAMPLE CODE [COMING SOON]
```

## License
BSD 3-Clause. See [LICENSE](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE) for details.

## Contacts
Email: <support@virgilsecurity.com>
