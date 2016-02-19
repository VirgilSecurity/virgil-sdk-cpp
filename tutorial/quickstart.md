# Quickstart C++

- [Introduction](#introduction)
- [Obtaining an Access Token](#obtaining-an-access-token)
- [Use case](#use-case)
    - [Initialization](#initialization)
    - [Step 1. Create and Publish the Keys](#step-1-create-and-publish-the-keys)
    - [Step 2. Encrypt and Sign](#step-2-encrypt-and-sign)
    - [Step 3. Get sender's Public Key](#step-3-get-senders-public-key)
    - [Step 4. Verify and Decrypt](#step-4-verify-and-decrypt)
- [Build](#build)
- [See also](#see-also)

## Introduction

This guide will help you get started using the Crypto Library and Virgil Keys Services for the most popular platforms and languages.
This branch focuses on the C++ library implementation and covers it's usage.


## Obtaining an Access Token

First you must create a free Virgil Security developer's account by signing up [here](https://developer.virgilsecurity.com/account/signup). Once you have your account you can [sign in](https://developer.virgilsecurity.com/account/signin) and generate an access token for your application.

The access token provides authenticated secure access to Virgil Keys Services and is passed with each API call. The access token also allows the API to associate your app’s requests with your Virgil Security developer's account.

Use this token to initialize the SDK client [here](#initialization).

## Use Case
**Secure data at transport**: users need to exchange important data (text, audio, video, etc.) without any risks.

- Sender and recipient create Virgil accounts with a pair of asymmetric keys:
    - public key on Virgil Public Keys Service;
    - private key on Virgil Private Keys Service or locally.
- Sender encrypts the data using Virgil Crypto Library and the recipient’s public key.
- Sender signs the encrypted data with his private key using Virgil Crypto Library.
- Sender securely transfers the encrypted data, his digital signature and UDID to the recipient without any risk to be revealed.
- Recipient verifies that the signature of transferred data is valid using the signature and sender’s public key in Virgil Crypto Library.
- Recipient decrypts the data with his private key using Virgil Crypto Library.
- Decrypted data is provided to the recipient.

## Initialization

``` {.cpp}
ServicesHub servicesHub(%ACCESS_TOKEN%);
```

## Step 1. Create and Publish the Keys
First we are generating the keys and publishing them to the Public Keys Service where they are available in an open access for other users (e.g. recipient) to verify and encrypt the data for the key owner.

The following code example creates a new public/private key pair.

``` {.cpp}
// Specify password in the constructor to store private key encrypted.
VirgilByteArray senderPrivateKeyPassword = str2bytes("PRIVATE_KEY_PASS")
VirgilKeyPair newKeyPair(senderPrivateKeyPassword);
VirgilByteArray senderPublicKey = newKeyPair.publicKey();
VirgilByteArray senderPrivateKey = newKeyPair.privateKey();
```

We are verifying whether the user really owns the provided email address and getting a temporary token for public key registration on the Public Keys Service.

``` {.cpp}
Identity identity(%SENDER_EMAIL%, IdentityType::Email);
std::string actionId = servicesHub.identity().verify(identity);

// use confirmation code sent to your email box.
ValidatedIdentity validatedIdentity =
        servicesHub.identity().confirm(actionId, "%CONFIRMATION_CODE%);
```

We are registering a Virgil Card which includes a public key and an email address identifier. The card will be used for the public key identification and searching for it in the Public Keys Service.

``` {.cpp}
Credentials credentials(senderPrivateKey, senderPrivateKeyPassword);
Card senderCard = servicesHub.card().create(validatedIdentity, senderPublicKey, credentials);
```

## Step 2. Encrypt and Sign
We are searching for the recipient's public key on the Public Keys Service to encrypt a message for him. And we are signing the encrypted message with our private key so that the recipient can make sure the message had been sent from the declared sender.

``` {.cpp}
auto message = "Encrypt me, Please!!!";

Identity identity(%RECIPIENT_EMAIL%, IdentityType::Email);
std::vector<Card> recipientCards = servicesHub.card().search(identity);
Card recipientCard = recipientCards.at(0);

VirgilCipher cipher;
cipher.addKeyRecipient(str2bytes(recipientCard.getId()),
        recipientCard.getPublicKey().getKey());
VirgilByteArray encryptedMessage = cipher.encrypt(str2bytes(message), true);

VirgilSigner signer;
VirgilByteArray signedEncryptedMessage = signer.sign(encryptedMessage, senderPrivateKey,
        senderPrivateKeyPassword);
```

## Step 3. Get sender's Public Key
In order to decrypt the received data the app on recipient’s side needs to get sender’s Virgil Card from the Public Keys Service.

``` {.cpp}
Identity identity(%SENDER_EMAIL%, IdentityType::Email);
std::vector<Card> senderCards = servicesHub.card().search(identity);
Card senderCard = senderCards.at(0);
```

## Step 4. Verify and Decrypt
We are making sure the letter came from the declared sender by getting his card on Public Keys Service. In case of success we are decrypting the letter using the recipient's private key.

``` {.cpp}
bool verified = signer.verify(encryptedMessage, signedEncryptedMessage,
        senderCard.getPublicKey().getKey());
if (!verified) {
    throw std::runtime_error("Signature is not valid.");
}

VirgilByteArray originalMessage = cipher.decryptWithKey(encryptedMessage, recipientCard.getId(),
        recipientPrivateKey, recipientPrivateKeyPassword
);
```

## Build

Run one of the following commands in the project's root folder.

  * Build Public Keys SDK

    * Unix:

            mkdir build && cd build && cmake -DVIRGIL_SDK_KEYS=ON .. && make -j4

    * Windows:

            mkdir build && cd build && cmake -DVIRGIL_SDK_KEYS=ON .. && nmake

  * Build Private Keys SDK

    * Unix:

            mkdir build && cd build && cmake -DVIRGIL_SDK_PRIVATE_KEYS=ON .. && make -j4

    * Windows:

            mkdir build && cd build && cmake -DVIRGIL_SDK_PRIVATE_KEYS=ON .. && nmake

  * Build Examples

    * Unix:

            mkdir build && cd build && cmake -DVIRGIL_EXAMPLES=ON .. && make -j4

    * Windows:

            mkdir build && cd build && cmake -DVIRGIL_EXAMPLES=ON .. && nmake


## See Also

* [Tutorial Crypto Library](virgil_crypto.md)
* [Tutorial SDK](virgil_sdk_cpp.md)
