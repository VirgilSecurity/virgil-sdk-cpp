# Virgil Security C++ library stack

- [Introduction](#introduction)
- [Obtaining an App Token](#obtaining-an-app-token)
- [Usage examples](#usage-examples)
    - [General statements](#general-statements)
    - [Example 1: Generate keys](#example-1)
    - [Example 2: Add user's public key](#example-2)
    - [Example 3: Get user's public key](#example-3)
    - [Example 4: Encrypt data](#example-4)
    - [Example 5: Decrypt data](#example-5)
    - [Example 6: Sign data](#example-6)
    - [Example 7: Verify data](#example-7)
- [License](#license)
- [Contacts](#contacts)

## Introduction
This guide will help you get started using the Crypto Library and Virgil Keys Service, for the most popular platforms and languages.

This branch focuses on the C++ library implementation and covers it's usage.

## Obtaining an Application Token
First you must create a free Virgil Security developer account by signing up [here](https://virgilsecurity.com/signup). Once you have your account you can [sign in](https://virgilsecurity.com/signin) and generate an app token for your application.

The application token provides authenticated secure access to Virgil’s Keys Service and is passed with each API call. The app token also allows the API to associate your app’s requests with your Virgil Security developer account.

Simply add your application token to the HTTP header for each request:
```
X-VIRGIL-APPLICATION-TOKEN: { YOUR_APPLICATION_TOKEN }
```

## Usage examples

This section describes common case library usage scenarios, like

- generate new keys;
- register user's public key on the Virgil PKI service;
- encrypt data for user identified by email, phone, etc;
- decrypt data with private key;
- sign data with private key;
- verify data with signer identified by email, phone, etc.

Full source code examples are available on [GitHub](https://github.com/VirgilSecurity/virgil-cpp/tree/master/examples) in public access.

### <a name="example-1"></a> Example 1: Generate keys
Working with Virgil Security Services it is requires the creation of both a public key and a private key. The public key can be made public to anyone using the Virgil Public Keys Service while the private key must be known only to the party or parties who will decrypt the data encrypted with the public key.

> __Private keys should never be stored verbatim or in plain text on the local computer.__<br>
> \- If you need to store a private key, you should use a secure key container depending on your platform. You also can use Virgil Security Services. This will allows you to easily synchronize private keys between clients devices and applications. Please read more about [Virgil Private Keys Service](https://virgilsecurity.com/documents/cpp/keys-service).

The following code example creates a new public/private key pair.
``` {.cpp}
VirgilKeyPair newKeyPair; // Specify password in the constructor to store private key encrypted.
VirgilByteArray publicKey = newKeyPair.publicKey();
VirgilByteArray privateKey = newKeyPair.privateKey();
```
### <a name="example-2"></a> Example 2: Register user

Once you've created a public key you may push it to Virgil’s Keys Service. This will allow other users to send you encrypted data using your public key.

This example shows how to upload a public key and register a new account on Virgil’s Keys Service.

``` {.cpp}
Credentials credentials(privateKey);
std::string uuid = "{random generated UUID}";
KeysClient keysClient("{Application Token}");
UserData userData = UserData::email("mail@server.com");
PublicKey virgilPublicKey = keysClient.publicKey().add(publicKey, {userData}, credentials, uuid);
```

Then Confirm User Data using your user data type (Currently supported only Email).

``` {.cpp}
auto userDataId = virgilPublicKey.userData().front().userDataId();
auto confirmationCode = ""; // Confirmation code you received on your email box.
KeysClient keysClient("{Application Token}");
keysClient.userData().confirm(userDataId, confirmationCode);
```

### <a name="example-3"></a> Example 3: Get user's public key

Get public key from Public Keys Service.

``` {.cpp}
KeysClient keysClient("{Application Token}");
PublicKey publicKey = keysClient.publicKey().grab("mail@server.com");
```

### <a name="example-4"></a> Example 4: Encrypt data

The procedure for encrypting and decrypting documents is straightforward with this mental model. For example: if you want to encrypt the data to Bob, you encrypt it using Bobs's public key which you can get from Public Keys Service, and he decrypts it with his private key. If Bob wants to encrypt data to you, he encrypts it using your public key, and you decrypt it with your private key.

In code example below data encrypted with public key previously loaded from Virgil's Public Keys Service.

``` {.cpp}
VirgilCipher cipher;
cipher.addKeyRecipient(virgil::crypto::str2bytes(publicKey.publicKeyId()), publicKey.key());
VirgilByteArray encryptedData = cipher.encrypt(virgil::crypto::str2bytes("Data to be encrypted."), true);
```

### <a name="example-5"></a> Example 5: Decrypt data

The following example illustrates the decryption of encrypted data by public key.

``` {.cpp}
VirgilByteArray decryptedData = cipher.decrypt(encryptedData, publicKey.publicKeyId(), privateKey);
```

### <a name="example-6"></a> Example 6: Sign data

Cryptographic digital signatures use public key algorithms to provide data integrity. When you sign data with a digital signature, someone else can verify the signature, and can prove that the data originated from you and was not altered after you signed it.

The following example applies a digital signature to public key identifier.

``` {.cpp}
VirgilSigner signer;
VirgilByteArray data = virgil::crypto::str2bytes("some data");
VirgilByteArray sign = signer.sign(data, privateKey);
```

### <a name="example-7"></a> Example 7: Verify data

To verify that data was signed by a particular party, you must have the following information:

* The public key of the party that signed the data.
* The digital signature.
* The data that was signed.

The following example verifies a digital signature which was signed by sender.

``` {.cpp}
bool verified = signer.verify(data, sign, publicKey.key());
```

## License
BSD 3-Clause. See [LICENSE](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE) for details.

## Contacts
Email: <support@virgilsecurity.com>
