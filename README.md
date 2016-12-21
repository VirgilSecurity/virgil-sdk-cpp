![VirgilSDK](https://cloud.githubusercontent.com/assets/6513916/19643783/bfbf78be-99f4-11e6-8d5a-a43394f2b9b2.png)

[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-sdk-cpp.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-sdk-cpp)
[![Documentation Doxygen](https://img.shields.io/badge/docs-doxygen-blue.svg)](http://VirgilSecurity.github.io/virgil-sdk-cpp)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/7135/badge.svg)](https://scan.coverity.com/projects/virgilsecurity-virgil-sdk-cpp)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-sdk-cpp/release/LICENSE)

# C++ SDK Programming Guide

Welcome to the SDK Programming Guide. This guide is a practical introduction to creating apps with Virgil Security features.

In this guide you will find code for every task you need to implement in order to create an application using Virgil Security services. It also includes a description of main classes and methods. The aim of this guide is to get you up and running quickly. You should be able to copy and paste the code provided into your own apps and use it with minumal changes.

## Table of Contents

* [Requirements](#requirements)
* [Installation](#installation)
* [User and App Credentials](#user-and-app-credentials)
* [Creating a Virgil Card](#creating-a-virgil-card)
* [Search for Virgil Cards](#search-for-virgil-cards)
* [Validating Virgil Cards](#validating-virgil-cards)
* [Get a Virgil Card](#get-a-virgil-card)
* [Revoking a Virgil Card](#revoking-a-virgil-card)
* [Operations with Crypto Keys](#operations-with-crypto-keys)
* [Generate Keys](#generate-keys)
* [Import and Export Keys](#import-and-export-keys)
* [Encryption and Decryption](#encryption-and-decryption)
* [Encrypt Data](#encrypt-data)
* [Decrypt Data](#decrypt-data)
* [Generating and Verifying Signatures](#generating-and-verifying-signatures)
* [Generating a Signature](#generating-a-signature)
* [Verifying a Signature](#verifying-a-signature)
* [Authenticated Encryption](#authenticated-encryption)
* [Fingerprint Generation](#fingerprint-generation)
* [Release Notes](#release-notes)

## Requirements

- C++14 compatible compiler
- CMake 3.2+

## Installation

TODO

## User and App Credentials

When you register an application on the Virgil developer's [dashboard](https://developer.virgilsecurity.com/dashboard), we provide you with an *appId*, *appKey* and *accessToken*.

* **appId** uniquely identifies your application in our services, it is also used to identify the Public key generated in a pair with *appKey*, for example: ```af6799a2f26376731abb9abf32b5f2ac0933013f42628498adb6b12702df1a87```
* **appKey** is a Private key that is used to perform creation and revocation of *Virgil Cards* (Public key) in Virgil services. Also the *appKey* can be used for cryptographic operations to take part in application logic. The *appKey* is generated at the time of application creation and has to be saved in secure place. 
* **accessToken** is a unique string value that provides an authenticated secure access to the Virgil services and is passed with each API call. The *accessToken* also allows the API to associate your app’s requests with your Virgil developer’s account. 

## Connecting to Virgil
Before you can use any Virgil services features in your app, you must first initialize ```Client``` class. You use the ```Client``` object to get access to Create, Revoke, Get and Search for *Virgil Cards* (Public keys). 

### Initializing an API Client

To create an instance of *Client* class, just call its constructor with your application's *accessToken* which you generated on developer's deshboard.

```cpp
Client client(<#Virgil App token#>);
```

### Initializing Crypto
The *Crypto* class provides cryptographic operations in applications, such as hashing, signature generation and verification, encryption and decryption.

```cpp
auto crypto = std::make_shared<Crypto>();
```

## Creating a Virgil Card

A *Virgil Card* is the main entity of the Virgil services, it includes the information about the user and his public key. The *Virgil Card* identifies the user/device by one of his types. 

Collect an *appId* and *appKey* for your app. These parametes are required to create a Virgil Card in your app scope.

```cpp
auto appId = <#String: Your appId#>;
auto appKeyPassword = <#String: You app key password#>;
auto privateAppKeyData = <#String: You app key data in Base64#>;

auto appPrivateKey = crypto->importPrivateKey(privateAppKeyData, appKeyPassword);
```

Generate a new Public/Private keypair using *Crypto* class. 

```cpp
auto aliceKeys = crypto->generateKeyPair();
```

Prepare request
```cpp
auto exportedPublicKey = crypto->exportPublicKey(aliceKeys.publicKey());
auto request = CreateCardRequest::createRequest("alice", "username", exportedPublicKey);
```

then, use *RequestSigner* class to sign request with owner and app keys.
```cpp
RequestSigner signer(crypto);

signer.selfSign(request, aliceKeys.privateKey());
signer.authoritySign(request, appId, appPrivateKey);
```

Publish a Virgil Card
```cpp
auto future = client.createCard(request);

auto card = future.get();
```

## Search for Virgil Cards
Performs the `Virgil Card`s search by criteria:
- the *Identities* request parameter is mandatory;
- the *IdentityType* is optional and specifies the *IdentityType* of a `Virgil Card`s to be found;
- the *Scope* optional request parameter specifies the scope to perform search on. Either 'global' or 'application';

```cpp
auto criteria = SearchCardsCriteria::createCriteria(CardScope::application, "username", {"alice", "bob"});

auto future = client.searchCards(criteria);

auto cards = future.get();
```

## Validating Virgil Cards
This sample uses *built-in* ```CardValidator``` to validate Virgil Service card responses. Default ```CardValidator``` validates only *Cards Service* signature. 

```cpp
auto validator = std::make_unique<CardValidator>(crypto);

// Your can also add another Public Key for verification.
// validator->addVerifier(<#Verifier card id#>, <#Verifier public key data#>);

auto isValid = validator->validateCardResponse(response);
```

For convenience you can embed validator into the client and all cards received from the Virgil service will be automatically validated for you.
If validation process failes during client queries, error will be thrown.

```cpp
auto crypto = std::make_shared<Crypto>();

auto validator = std::make_unique<CardValidator>(crypto);
validator->addVerifier(<#Verifier card id#>, publicKey: <#Verifier public key data#>);

auto serviceConfig = ServiceConfig::createConfig(<#Virgil App token#>);
serviceConfig.cardValidator(std::move(validator));

Client client(std::move(serviceConfig));
```

## Get a Virgil Card
```cpp
auto future = client.getCard(<#Your cardId#>);

auto card = future.get();
```

## Revoking a Virgil Card

You can make Virgil Card unavailable for further use if its private key was compromised or for any other reason.

```cpp
auto revokeRequest = RevokeCardRequest::createRequest(<#Your cardId#>, CardRevocationReason::unspecified);

RequestSigner signer(crypto);


signer.authoritySign(revokeRequest, appId, appPrivateKey);

auto future = client.revokeCard(revokeRequest);

future.get();
```

## Operations with Crypto Keys

### Generate Keys
The following code sample illustrates keypair generation. The default algorithm is ed25519

```cpp
auto aliceKeys = crypto->generateKeyPair();
```

### Import and Export Keys
You can export and import your Public/Private keys to/from supported wire representation.

To export Public/Private keys, simply call one of the Export methods:

```cpp
auto alicePrivateKeyData = crypto->exportPrivateKey(aliceKeys.privateKey(), "password");
auto alicePublicKeyData = crypto->exportPublicKey(aliceKeys.publicKey());
```

To import Public/Private keys, simply call one of the Import methods:

```cpp
auto alicePrivateKey = crypto->importPrivateKey(alicePrivateKeyData, "password");
auto alicePublicKey = crypto->importPublicKey(alicePublicKeyData);
```

## Encryption and Decryption

Initialize Crypto API and generate keypair.

```cpp
auto crypto = std::make_shared<Crypto>();
auto keyPair = crypto->generateKeyPair();
```

### Encrypt Data
Data encryption using ECIES scheme with AES-GCM. You can encrypt either stream or data.
There also can be more than one recipient

*Data*
```cpp
auto plainTextData = VirgilByteArrayUtils::stringToBytes("Hello, Bob!");
auto encryptedData = crypto->encrypt(plainTextData, { aliceKeys.publicKey() });
```

*Stream*
```cpp
std::ifstream inputFileStream("input");
std::ofstream outputFileStream("output");

crypto->encrypt(inputFileStream, outputFileStream, { aliceKeys.publicKey() });
```

### Decrypt Data
You can decrypt either stream or data using your private key

*Data*
```cpp
auto decrytedData = crypto->decrypt(encryptedData, aliceKeys.privateKey());
```

*Stream*
```cpp
std::ifstream inputFileStream("input");
std::ofstream outputFileStream("output");

crypto->decrypt(inputFileStream, outputFileStream, aliceKeys.privateKey());
```

## Generating and Verifying Signatures
This section walks you through the steps necessary to use the *VirgilCrypto* to generate a digital signature for data and to verify that a signature is authentic.

### Generating a Signature

Sign the SHA-384 fingerprint of either stream or data using your private key. To generate the signature, simply call one of the sign methods:

*Data*
```cpp
auto plainTextData = VirgilByteArrayUtils::stringToBytes("Hello, Bob!");
auto signature = crypto->generateSignature(plainTextData, aliceKeys.privateKey());
```

*Stream*
```cpp
std::ifstream inputFileStream("input");
auto signature = crypto->generateSignature(plainTextData, aliceKeys.privateKey());
```

### Verifying a Signature

Verify the signature of the SHA-384 fingerprint of either stream or a data using Public key. The signature can now be verified by calling the verify method:

```cpp
auto isVerified = crypto->verify(data, signature, aliceKeys.publicKey());
```

*Stream*
```cpp
auto isVerified = crypto->verify(stream, signature, aliceKeys.publicKey());
```

## Authenticated Encryption
Virgil SDK contains convenient API for combining encrypt/decrypt and sign/verify procedures

*Sign and encrypt*
```cpp
auto signedAndEcryptedData = crypto->signThenEncrypt(data, senderPrivateKey, { receiverPublicKey });
```

*Decrypt and verify*
```cpp
auto decryptedAndVerifiedData = crypto->decryptThenVerify(signedAndEcryptedData, receiverPrivateKey, senderPublicKey);
```

## Fingerprint Generation
The default Fingerprint algorithm is SHA-256.
```cpp
auto fingerprint = crypto->calculateFingerprint(data);
```

## Release Notes
- Please read the latest note here: [https://github.com/VirgilSecurity/virgil-sdk-cpp/releases](https://github.com/VirgilSecurity/virgil-sdk-cpp/releases)