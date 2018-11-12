# Virgil Security C++ SDK

[![Build Status](https://travis-ci.com/VirgilSecurity/sdk-cpp.svg?branch=master)](https://travis-ci.com/VirgilSecurity/sdk-cpp)
[![Documentation Doxygen](https://img.shields.io/badge/docs-doxygen-blue.svg)](http://VirgilSecurity.github.io/sdk-cpp)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-sdk-cpp/release/LICENSE)


[Introduction](#introduction) | [SDK Features](#sdk-features) | [Installation](#installation) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a>[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.

The Virgil SDK allows developers to get up and running with Virgil API quickly and add full end-to-end security to their existing digital solutions to become HIPAA and GDPR compliant and more.

## SDK Features
- communicate with [Virgil Cards Service][_cards_service]
- manage users' Public Keys
- use Virgil [Crypto library][_virgil_crypto]

## Installation
### Requirements

- C++11 compatible compiler
- CMake 3.10+

### CMake
Virgil SDK can be integrated using CMake in different ways

#### Add downloaded sources as subdirectory

```cmake
add_subdirectory (<PATH_TO_DEPENDENCIES>/sdk-cpp sdk-cpp)

target_link_libraries (${PROJECT_NAME} virgil_sdk)
```

#### Use custom CMake util
You can find file called *virgil_depends_local.cmake* at *sdk-cpp/cmake/utils*.
This is in-house dependency loader based on pure CMake features.

Usage:
  - Create cmake configuration file for target dependency
```cmake
cmake_minimum_required (VERSION @CMAKE_VERSION@ FATAL_ERROR)

project ("@VIRGIL_DEPENDS_PACKAGE_NAME@-depends")

include (ExternalProject)

# Configure additional CMake parameters
file (WRITE "@VIRGIL_DEPENDS_ARGS_FILE@"
  "set (ENABLE_TESTING OFF CACHE INTERNAL \"\")\n"
  "set (INSTALL_EXT_LIBS ON CACHE INTERNAL \"\")\n"
  "set (INSTALL_EXT_HEADERS ON CACHE INTERNAL \"\")\n"
  "set (UCLIBC @UCLIBC@ CACHE INTERNAL \"\")\n"
)

ExternalProject_Add (${PROJECT_NAME}
  DOWNLOAD_DIR "@VIRGIL_DEPENDS_PACKAGE_DOWNLOAD_DIR@"
  URL "https://github.com/VirgilSecurity/sdk-cpp/archive/v5.0.0.tar.gz"
  URL_HASH SHA1=<PUT_PACKAGE_HASH_HERE>
  PREFIX "@VIRGIL_DEPENDS_PACKAGE_BUILD_DIR@"
  CMAKE_ARGS "@VIRGIL_DEPENDS_CMAKE_ARGS@"
)

add_custom_target ("${PROJECT_NAME}-build" ALL COMMENT "Build package ${PROJECT_NAME}")
add_dependencies ("${PROJECT_NAME}-build" ${PROJECT_NAME})
```
  - In the project just put
```cmake
include (virgil_depends)

virgil_depends (
  PACKAGE_NAME "virgil_sdk"
  CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dir_to_config_file_from_step_1"
)

virgil_find_package (virgil_sdk)
```

## Usage Examples

Before starting practicing with the usage examples, make sure that the SDK is configured. Check out our [SDK configuration guides][_configure_sdk] for more information.

#### Generate and publish user's Cards with Public Keys inside on Cards Service
Use the following lines of code to create and publish a user's Card with Public Key inside on Virgil Cards Service:

```cpp
#include <virgil/sdk/cards/CardManager.h>

using virgil::sdk::crypto::Crypto;
using virgil::sdk::cards::CardManager;

// use Virgil Crypto
auto crypto = std::make_shared<Crypto>();

// generate a key pair
auto keyPair = crypto->generateKeyPair();

// publish card on Cards Service
auto future = cardManager.publishCard(keyPair.privateKey(), keyPair.publicKey());
auto card = future.get();
```

#### Sign then encrypt data

Virgil SDK allows you to use a user's Private key and his or her Cards to sign, then encrypt any kind of data.

In the following example, we load a Private Key from a customized Key Storage and get recipient's Card from the Virgil Cards Services. Recipient's Card contains a Public Key which we will encrypt the data and verify a signature with.

```cpp
#include <virgil/sdk/cards/CardManager.h>

using virgil::sdk::cards::CardManager;
using virgil::sdk::crypto::keys::PublicKey;
using virgil::sdk::VirgilByteArrayUtils;

// prepare a message
auto messageToEncrypt = "Hello, Bob!";
auto dataToEncrypt = VirgilByteArrayUtils::stringToBytes(messageToEncrypt);

// using cardManager search for Bob's cards on Cards Service
auto future = cardManager.searchCards("Bob");
auto bobCards = future.get();

auto bobRelevantCardsPublicKeys = std::vector<PublicKey>();

for (auto& card : bobCards)
  bobRelevantCardsPublicKeys.push_back(card.publicKey());

// sign a message with a private key then encrypt using Bob's public keys
auto encryptedData = crypto->signThenEncrypt(dataToEncrypt, alicePrivateKey, bobRelevantCardsPublicKeys);
```

#### Decrypt then verify data
Once the Users have received the signed and encrypted message, they can decrypt it with their own Private Key and verify the signature with Sender's Card:

```cpp
#include <virgil/sdk/cards/CardManager.h>

using virgil::sdk::cards::CardManager;
using virgil::sdk::crypto::keys::PublicKey;

// using cardManager search for Alice's cards on Cards Service
auto future = cardManager.searchCards("Alice");
auto aliceCards = future.get();

auto aliceRelevantCardsPublicKeys = std::vector<PublicKey>();

for (auto& card : aliceCards)
  aliceRelevantCardsPublicKeys.push_back(card.publicKey());

// decrypt with a private key and verify using one of Alice's public keys
auto decryptedData = crypto->decryptThenVerify(encryptedData, bobPrivateKey, aliceRelevantCardsPublicKeys);
```

## Docs
Virgil Security has a powerful set of APIs, and the documentation below can get you started today.

In order to use the Virgil SDK with your application, you will need to configure your application first. By default, 
the SDK will attempt to look for Virgil-specific settings in your application but you can change it during SDK 
configuration.

* [Configure the SDK][_configure_sdk] documentation
  * [Setup authentication][_setup_authentication] to make API calls to Virgil Services
  * [Setup Card Manager][_card_manager] to manage user's Public Keys
  * [Setup Card Verifier][_card_verifier] to verify signatures inside of user's Card
  * [Setup Key storage][_key_storage] to store Private Keys
  * [Setup your own Crypto library][_own_crypto] inside of the SDK
* [More usage examples][_more_examples]
  * [Create & publish a Card][_create_card] that has a Public Key on Virgil Cards Service
  * [Search user's Card by user's identity][_search_card]
  * [Get user's Card by its ID][_get_card]
  * [Use Card for crypto operations][_use_card]
* [API Reference][_reference_api]

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.slack.com/join/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).

[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto
[_cards_service]: https://developer.virgilsecurity.com/docs/api-reference/card-service/v5
[_use_card]: https://developer.virgilsecurity.com/docs/cpp/how-to/public-key-management/v5/use-card-for-crypto-operation
[_get_card]: https://developer.virgilsecurity.com/docs/cpp/how-to/public-key-management/v5/get-card
[_search_card]: https://developer.virgilsecurity.com/docs/cpp/how-to/public-key-management/v5/search-card
[_create_card]: https://developer.virgilsecurity.com/docs/cpp/how-to/public-key-management/v5/create-card
[_own_crypto]: https://developer.virgilsecurity.com/docs/cpp/how-to/setup/v5/setup-own-crypto-library
[_key_storage]: https://developer.virgilsecurity.com/docs/cpp/how-to/setup/v5/setup-key-storage
[_card_verifier]: https://developer.virgilsecurity.com/docs/cpp/how-to/setup/v5/setup-card-verifier
[_card_manager]: https://developer.virgilsecurity.com/docs/cpp/how-to/setup/v5/setup-card-manager
[_setup_authentication]: https://developer.virgilsecurity.com/docs/cpp/how-to/setup/v5/setup-authentication
[_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
[_configure_sdk]: https://developer.virgilsecurity.com/docs/how-to#sdk-configuration
[_more_examples]: https://developer.virgilsecurity.com/docs/how-to#public-key-management
