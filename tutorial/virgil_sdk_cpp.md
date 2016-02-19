# Tutorial C++ Keys SDK

- [Introduction](#introduction)
- [Obtaining an Access Token](#obtaining-an-access-token)
- [Identity Check](#identity-check)
  - [Identity Verification](#Identity-verification)
  - [Confirm and Get an Validated Identity](#confirm-and-get-an-validated-identity)
- [Cards and Public Keys](#cards-and-public-keys)
  - [Publish a Card](#publish-a-virgil-card)
  - [Search for Cards](#search-for-cards)
  - [Search for Application Cards](#search-for-application-cards)
  - [Sign a Virgil Card](#sign-a-virgil-card)
  - [Unsign a Virgil Card](#unsign-a-virgil-card)
  - [Revoke a Virgil Card](#revoke-a-virgil-card)
  - [Get a Public Key](#get-a-public-key)
- [Private Keys](#private-keys)
  - [Add a Private Key](#add-a-private-key)
  - [Get a Private Key](#get-a-private-key)
  - [Delete a Private Key](#delete-a-private-key)
- [Build](#build)
- [See also](#see-also)

## Introduction

This tutorial explains how to use the Identity, Public Keys, Private Keys Service with SDK library in C++ applications.

## Obtaining an Access Token

First you must create a free Virgil Security developer's account by signing up [here](https://virgilsecurity.com/account/signup). Once you have your account you can [sign in](https://virgilsecurity.com/account/signin) and generate an access token for your application.

The access token provides an authenticated secure access to the Public Keys Service and is passed with each API call. The access token also allows the API to associate your app’s requests with your Virgil Security developer's account.

Simply add your access token to the client constuctor.

``` {.cpp}
ServicesHub servicesHub(%ACCESS_TOKEN%);
```

## Identity Check

All the Virgil Security services are strongly interconnected with the Identity Service. It determines the ownership of the identity being checked using particular mechanisms and as a result it generates a temporary token to be used for the operations which require an identity verification.

#### Identity Verification

Initialize the identity verification process.

``` {.cpp}
Identity identity(%YOUR_EMAIL%, IdentityType::Email);
std::string actionId = servicesHub.identity().verify(identity);
```
See a working example [here...](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/v3/examples/src/identity_verify.cxx)


#### Confirm and Get an Identity Token

Confirm the identity and get a temporary token.

``` {.cpp}
// use confirmation code sent to your email box.
ValidatedIdentity validatedIdentity =
        servicesHub.identity().confirm(actionId, "%CONFIRMATION_CODE%);
```
See a working example [here...](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/v3/examples/src/identity_confirm.cxx)


## Cards and Public Keys

A Virgil Card is the main entity of the Public Keys Service, it includes the information about the user and his public key. The Virgil Card identifies the user by one of his available types, such as an email, a phone number, etc.

#### Publish a Virgil Card

An identity token which can be received [here](#identity-check) is used during the registration.

``` {.cpp}
VirgilByteArray privateKeyPassword = str2bytes("PRIVATE_KEY_PASS")
VirgilKeyPair keyPair(privateKeyPassword);
Credentials credentials(keyPair.privateKey(), privateKeyPassword);
Card myCard = servicesHub.card().create(validatedIdentity, keyPair.publicKey(), credentials);
```
See a working example [here...](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/v3/examples/src/card_create.cxx)


#### Search for Cards

Search for the Virgil Card by provided parameters.

``` {.cpp}
Identity identity(%USER_EMAIL%, IdentityType::Email);
std::vector<Card> foundCards = servicesHub.card().search(identity);
```
See a working example [here...](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/v3/examples/src/card_search.cxx)


#### Search for Application Cards

Search for the Virgil Cards by a defined pattern. The example below returns a list of applications for Virgil Security company.

``` {.cpp}
std::vector<Card> allAppCards = servicesHub.card().searchApp("com.virgil.*");
```
See a working example [here...](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/v3/examples/src/card_search_app.cxx)


#### Sign a Virgil Card

Any Virgil Card user can act as a certification center within the Virgil Security ecosystem. Every user can certify another's Virgil Card and build a net of sign based on it.

The example below demonstrates how to certify a user's Virgil Card by signing its hash attribute.

``` {.cpp}
Credentials signerCredentials(signerPrivateKey, str2bytes(SIGNER_PRIVATE_KEY_PASSWORD));
CardSign cardSign = servicesHub.card().sign(toBeSignedCardId, toBeSignedCardHash, signerCardId,
        signerCredentials);
```
See a working example [here...](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/v3/examples/src/card_sign.cxx)


#### Unsign a Virgil Card

Naturally it is possible to stop signing the Virgil Card owner as in all relations. This is not an exception in Virgil Security system.

``` {.cpp}
servicesHub.card().unsign(signedCardId, signerCardId, signerCredentials);
```
See a working example [here...](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/v3/examples/src/card_unsign.cxx)


#### Revoke a Virgil Card

This operation is used to delete the Virgil Card from the search and mark it as deleted.

``` {.cpp}
servicesHub.card().revoke(ownerCardId, ownerValidatedIdentity, ownerCredentials);
```
See a working example [here...](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/v3/examples/src/card_revoke.cxx)


#### Get a Public Key

Gets a public key from the Public Keys Service by the specified ID.

``` {.cpp}
PublicKey publicKey = servicesHub.publicKey().get(publicKeyId);
```
See a working example [here...](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/v3/examples/src/public_key_get.cxx)


## Private Keys

The security of private keys is crucial for the public key cryptosystems. Anyone who can obtain a private key can use it to impersonate the rightful owner during all communications and transactions on intranets or on the internet. Therefore, private keys must be in the possession only of authorized users, and they must be protected from unauthorized use.

Virgil Security provides a set of tools and services for storing private keys in a safe storage which lets you synchronize your private keys between the devices and applications.

Usage of this service is optional.

#### Add a Private Key

Private key can be added for storage only in case you have already registered a public key on the Public Keys Service.

Use the public key identifier on the Public Keys Service to save the private keys.

The Private Keys Service stores private keys the original way as they were transferred. That's why we strongly recommend to trasfer the keys which were generated with a password.

``` {.cpp}
servicesHub.privateKey().add(cardId, credentials);
```
See a working example [here...](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/v3/examples/src/private_key_add.cxx)


#### Get a Private Key

To get a private key you need to pass a prior verification of the Virgil Card where your public key is used.

``` {.cpp}
PrivateKey privateKey = servicesHub.privateKey().get(cardId, validatedIdentity);
```
See a working example [here...](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/v3/examples/src/private_key_get.cxx)


#### Delete a Private Key

This operation deletes the private key from the service without a possibility to be restored.

``` {.cpp}
servicesHub.privateKey().del(cardId, credentials);
```
See a working example [here...](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/v3/examples/src/private_key_delete.cxx)


## Build

Run one of the following commands in the project's root folder.
  * Build SDK

    * Unix:

            mkdir build && cd build && cmake .. && make -j4

    * Windows:

            mkdir build && cd build && cmake .. && nmake


  * Build Examples

    * Unix:

            mkdir build && cd build && cmake -DVIRGIL_EXAMPLES=ON .. && make -j4

    * Windows:

            mkdir build && cd build && cmake -DVIRGIL_EXAMPLES=ON .. && nmake


## See Also

* [Quickstart](quickstart.md)
* [Reference API for SDK](http://virgilsecurity.github.io/virgil-sdk-cpp/)

