# Virgil Core SDK C++

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-sdk-cpp.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-sdk-cpp)
[![Documentation Doxygen](https://img.shields.io/badge/docs-doxygen-blue.svg)](http://VirgilSecurity.github.io/virgil-sdk-cpp)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-sdk-cpp/release/LICENSE)


[Introduction](#introduction) | [SDK Features](#sdk-features) | [Crypto Library Purposes](#crypto-library-purposes) | [Installation](#installation) | [Configure SDK](#configure-sdk) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application. In a few simple steps you can encrypt communication, securely store data, provide passwordless login, and ensure data integrity.

The Virgil Core SDK allows developers to get up and running with Virgil API quickly and add full end-to-end security to their existing digital solutions to become HIPAA and GDPR compliant and more.

## SDK Features
- Communicate with [Virgil Cards Service](https://developer.virgilsecurity.com/docs/platform/api-reference/cards-service/)
- Manage users' public keys
- Encrypt, sign, decrypt and verify data
- Store private keys in secure local storage
- Use Virgil [Crypto Library](https://github.com/VirgilSecurity/virgil-crypto-javascript)
- Use your own crypto library

## Crypto Library Purposes
* Asymmetric Key Generation
* Encryption/Decryption of data and streams
* Generation/Verification of digital signatures
* PFS (Perfect Forward Secrecy)
* **Post quantum algorithms support**. [Round5](https://round5.org/) (ecnryption) and [Falcon](https://falcon-sign.info/) (signature) 

## Installation

The Virgil Core SDK С++ is provided as a package named virgil_sdk.

#### Requirements

- C++11 compatible compiler
- CMake 3.10+

### CMake
Virgil SDK can be integrated using CMake in different ways:

#### Add downloaded sources as subdirectory

```cmake
add_subdirectory (<PATH_TO_DEPENDENCIES>/virgil-sdk-cpp virgil-sdk-cpp)

target_link_libraries (${PROJECT_NAME} virgil_sdk)
```

#### Use custom CMake util
You can find file called *virgil_depends_local.cmake* at *virgil-sdk-cpp/cmake/utils*.
This is an in-house dependency loader based on pure CMake features.

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
  URL "https://github.com/VirgilSecurity/virgil-sdk-cpp/archive/v5.0.0.tar.gz"
  URL_HASH SHA1=<PUT_PACKAGE_HASH_HERE>
  PREFIX "@VIRGIL_DEPENDS_PACKAGE_BUILD_DIR@"
  CMAKE_ARGS "@VIRGIL_DEPENDS_CMAKE_ARGS@"
)

add_custom_target ("${PROJECT_NAME}-build" ALL COMMENT "Build package ${PROJECT_NAME}")
add_dependencies ("${PROJECT_NAME}-build" ${PROJECT_NAME})
```
  - In the project, add the following code
```cmake
include (virgil_depends)

virgil_depends (
  PACKAGE_NAME "virgil_sdk"
  CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dir_to_config_file_from_step_1"
)

virgil_find_package (virgil_sdk)
```

## Configure SDK

This section contains guides on how to set up Virgil Core SDK modules for authenticating users, managing Virgil Cards and storing private keys.

### Set up authentication

Set up user authentication with tokens that are based on the [JSON Web Token standard](https://jwt.io/) with some Virgil modifications.

In order to make calls to Virgil Services (for example, to publish user's Card on Virgil Cards Service), you need to have a JSON Web Token ("JWT") that contains the user's `identity`, which is a string that uniquely identifies each user in your application.

Credentials that you'll need:

|Parameter|Description|
|--- |--- |
|App ID|ID of your Application at [Virgil Dashboard](https://dashboard.virgilsecurity.com)|
|App Key ID|A unique string value that identifies your account at the Virgil developer portal|
|App Key|A Private Key that is used to sign API calls to Virgil Services. For security, you will only be shown the App Key when the key is created. Don't forget to save it in a secure location for the next step|

#### Set up JWT provider on Client side

Use these lines of code to specify which JWT generation source you prefer to use in your project:

```cpp
#include <virgil/sdk/jwt/providers/CachingJwtProvider.h>

using virgil::sdk::jwt::TokenContext;
using virgil::sdk::jwt::providers::CachingJwtProvider;

// Get generated token from server-side
auto authenticatedQueryToServerSide = [&](const TokenContext& context) {
    std::promise<std::string> p;
    p.set_value("<TOKEN_FETCHED_FROM_SERVER>");

    return p.get_future();
};

// Setup AccessTokenProvider
auto provider = std::make_shared<CachingJwtProvider>(authenticatedQueryToServerSide);
```

#### Generate JWT on Server side

Next, you'll need to set up the `JwtGenerator` and generate a JWT using the Virgil SDK.

Here is an example of how to generate a JWT:

```cpp
#include <virgil/sdk/jwt/JwtGenerator.h>
#include <virgil/sdk/crypto/Crypto.h>

using virgil::sdk::jwt::JwtGenerator;
using virgil::sdk::VirgilBase64;
using virgil::sdk::crypto::Crypto;    

// App Key (you got this Key at Virgil Dashboard)
auto appKeyBase64 = "MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBC7Sg/DbNzhJ/uakTvafUMoAgIUtzAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEEDunQ1yhWZoKaLaDFgjpxRwEQAFdbC8e6103lJrUhY9ahyUA8+4rTJKZCmdTlCDPvoWH/5N5kxbOvTtbxtxevI421z3gRbjAtoWkfWraSLD6gj0=";
auto privateKeyData = VirgilBase64::decode(appKeyBase64);

// Crypto library imports a private key into a necessary format
auto crypto = std::shared_ptr<Crypto>();
auto appKey = crypto->importPrivateKey(privateKeyData);

// use your App Credentials you got at Virgil Dashboard:
auto appId = "be00e10e4e1f4bf58f9b4dc85d79c77a"; // App ID
auto appKeyId = "70b447e321f3a0fd"; // App Key ID
int ttl = 60 * 60 * 24; // 1 hour (JWT's lifetime)

// setup JWT generator with necessary parameters:
auto jwtGenerator = JwtGenerator(appKey, appKeyId, crypto, appId, ttl);

// generate JWT for a user
// remember that you must provide each user with his unique JWT
// each JWT contains unique user's identity (in this case - Alice)
// identity can be any value: name, email, some id etc.
auto identity = "Alice";
auto aliceJwt = jwtGenerator.generateToken(identity);

// as result you get users JWT, it looks like this: "eyJraWQiOiI3MGI0NDdlMzIxZjNhMGZkIiwidHlwIjoiSldUIiwiYWxnIjoiVkVEUzUxMiIsImN0eSI6InZpcmdpbC1qd3Q7dj0xIn0.eyJleHAiOjE1MTg2OTg5MTcsImlzcyI6InZpcmdpbC1iZTAwZTEwZTRlMWY0YmY1OGY5YjRkYzg1ZDc5Yzc3YSIsInN1YiI6ImlkZW50aXR5LUFsaWNlIiwiaWF0IjoxNTE4NjEyNTE3fQ.MFEwDQYJYIZIAWUDBAIDBQAEQP4Yo3yjmt8WWJ5mqs3Yrqc_VzG6nBtrW2KIjP-kxiIJL_7Wv0pqty7PDbDoGhkX8CJa6UOdyn3rBWRvMK7p7Ak"
// you can provide users with JWT at registration or authorization steps
// Send a JWT to client-side
auto jwtString = aliceJwt.stringRepresentation();
```

For this subsection we've created a sample backend that demonstrates how you can set up your backend to generate the JWTs. To set up and run the sample backend locally, head over to your GitHub repo of choice:

[Node.js](https://github.com/VirgilSecurity/sample-backend-nodejs) | [Golang](https://github.com/VirgilSecurity/sample-backend-go) | [PHP](https://github.com/VirgilSecurity/sample-backend-php) | [Java](https://github.com/VirgilSecurity/sample-backend-java) | [Python](https://github.com/VirgilSecurity/virgil-sdk-python/tree/master#sample-backend-for-jwt-generation)
 and follow the instructions in README.
 
### Set up Card Verifier

Virgil Card Verifier helps you automatically verify signatures of a user's Card, for example when you get a Card from Virgil Cards Service.

By default, `VirgilCardVerifier` verifies only two signatures - those of a Card owner and Virgil Cards Service.

Set up `VirgilCardVerifier` with the following lines of code:

```cpp
#include <virgil/sdk/cards/verification/VirgilCardVerifier.h>

using virgil::sdk::VirgilBase64;
using virgil::sdk::cards::verification::VirgilCardVerifier;
using virgil::sdk::cards::verification::VerifierCredentials;
using virgil::sdk::cards::verification::Whitelist;
using virgil::sdk::crypto::Crypto;

auto crypto = std::shared_ptr<Crypto>();

auto publicKeyData = VirgilBase64::decode(publicKeyStr);
auto yourBackendVerifierCredentials = VerifierCredentials("YOUR_BACKEND", publicKeyData);

auto yourBackendWhitelist = Whitelist({ yourBackendVerifierCredentials });

auto cardVerifier = VirgilCardVerifier(crypto, { yourBackendWhitelist });
```

### Set up Card Manager

This subsection shows how to set up a Card Manager module to help you manage users' public keys.

With Card Manager you can:
- specify an access Token (JWT) Provider.
- specify a Card Verifier used to verify signatures of your users, your App Server, Virgil Services (optional).

Use the following lines of code to set up the Card Manager:

```cpp
#include <virgil/sdk/cards/CardManager.h>

using virgil::sdk::cards::CardManager;

// initialize cardManager and specify accessTokenProvider, cardVerifier
auto cardManager = CardManager(crypto, accessTokenProvider, cardVerifier);
```


## Usage Examples

Before you start practicing with the usage examples, make sure that the SDK is configured. See the [Configure SDK](#configure-sdk) section for more information.

### Generate and publish Virgil Cards at Cards Service

Use the following lines of code to create a user's Card with a public key inside and publish it at Virgil Cards Service:

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

### Sign then encrypt data

Virgil Core SDK allows you to use a user's private key and their Virgil Cards to sign and encrypt any kind of data.

In the following example, we load a private key from a customized key storage and get recipient's Card from the Virgil Cards Service. Recipient's Card contains a public key which we will use to encrypt the data and verify a signature.

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

### Decrypt data and verify signature

Once the user receives the signed and encrypted message, they can decrypt it with their own private key and verify the signature with the sender's Card:

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

### Get Card by its ID

Use the following lines of code to get a user's card from Virgil Cloud by its ID:

```cpp
#include <virgil/sdk/cards/CardManager.h>

using virgil::sdk::cards::CardManager;

// using cardManager get a user's card from the Cards Service
auto getFuture = cardManager.getCard("f4bf9f7fcbedaba0392f108c59d8f4a38b3838efb64877380171b54475c2ade8");
auto card = getFuture.get()
```

### Get Card by user's identity

For a single user, use the following lines of code to get a user's Card by a user's `identity`:

```cpp
#include <virgil/sdk/cards/CardManager.h>

using virgil::sdk::cards::CardManager;

// using cardManager search for user's cards on Cards Service
auto searchFuture = cardManager.searchCards("Bob");
auto cards = searchFuture.get();
```

## Docs

Virgil Security has a powerful set of APIs, and the [Developer Documentation](https://developer.virgilsecurity.com/) can get you started today.

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support

Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
