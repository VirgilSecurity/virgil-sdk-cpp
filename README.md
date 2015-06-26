# Virgil Security C++ library stack

- [Introduction](#introduction)
- [Obtaining an App Token](#obtaining-an-app-token)
- [Usage examples](#usage-examples)
    - [General statements](#general-statements)
    - [Example 1: Generate keys](#example-1)
    - [Example 2: Register user](#example-2)
    - [Example 3: Get user's public key](#example-3)
    - [Example 4: Encrypt data](#example-4)
    - [Example 5: Decrypt data](#example-5)
    - [Example 6: Sign data](#example-6)
    - [Example 7: Verify data](#example-7)
- [License](#license)
- [Contacts](#contacts)

## Introduction
This documentation helps you to star developing secure apps using Virgil services.

This branch focuses on the C++ library implementation and covers it's usage.

## Obtaining an App Token
To use the Public Keys Service, you will first need to sign in with your developer account on developers [dashboard](https://virgilsecurity.com/dashboard) and generate app token for your application. If you do not have a Virgil Security account, you can create one here https://virgilsecurity.com/signup.

The app token is passed with each API call and is used to authenticate you access to the Public Keys service. It provides a secure access to the Public Keys service and allows the API to associate your application’s requests with your Virgil Security developer account.

Simply add your app token to HTTP header to each request:
```
X-VIRGIL-APP-TOKEN: { YOUR_APP_TOKEN }
```

## Usage examples

This section describes common case library usage scenarios, like

- generate new keys;
- register user on the Virgil PKI service;
- encrypt data for user identified by email, phone, etc;
- decrypt data with private key;
- sign data with private key;
- verify data with signer identified by email, phone, etc.

### <a name="example-1"></a> Example 1: Generate keys
To start working with Virgil Security Services it is require the creation of a public key and a private key. The public key can be made public to anyone using Public Keys Service, while the private key must known only by the party who will decrypt the data encrypted with the public key.

> __Private keys should never be stored verbatim or in plain text on the local computer.__<br>
> \- If you need to store a private key, you should use a secure key container depending on your platform. You also can use Virgil Security Services. This will allows you to easily synchronize private keys between clients devices and applications. Please read more about [Keys Service](https://virgilsecurity.com/documents/cpp/keys-service).

The following code example creates a new public/private key pair.
``` {.cpp}
VirgilKeyPair newKeyPair; // Specify password in the constructor to store private key encrypted.
VirgilByteArray publicKey = newKeyPair.publicKey();
VirgilByteArray privateKey = newKeyPair.privateKey();
```
### <a name="example-2"></a> Example 2: Register user

Once you've created public key you may push it to the Public Keys Service. This will allow other users to send you encrypted data using your public key.

This example shows how to upload public key and register new account on Public Keys Service.

``` {.cpp}
PkiClientBase pkiClient(std::make_shared<ConnectionBase>("{Token}"));
UserData userData = UserData().className("user_id").type("email").value("mail@server.com");
PublicKey virgilPublicKey = pkiClient.publicKey().add(publicKey, {userData});
```

### <a name="example-3"></a> Example 3: Get user's public key

Get public key from Public Keys Service.

``` {.cpp}
PkiClientBase pkiClient(std::make_shared<ConnectionBase>("{Token}"));
auto virgilAccount = pkiClient.publicKey().search(publicKey, {userData});
```

### <a name="example-4"></a> Example 4: Encrypt data

The procedure for encrypting and decrypting documents is straightforward with this mental model. For example: if you want to encrypt the data to Bob, you encrypt it using Bobs's public key which you can get from Public Keys Service, and he decrypts it with his private key. If Bob wants to encrypt data to you, he encrypts it using your public key, and you decrypt it with your private key.

In code example below data encrypted with public key previously loaded from Public Keys Service.

``` {.cpp}
VirgilCipher cipher;
cipher.addKeyRecipient(virgil::str2bytes(publicKey.publicKeyId()), publicKey.key());
VirgilByteArray encryptedData = cipher.encrypt(virgil::str2bytes("Data to be encrypted."), true);
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
VirgilByteArray data = virgil::str2bytes("some data");
VirgilByteArray sign = signer.sign(data, privateKey);
```

### <a name="example-6"></a> Example 7: Verify data

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
