# C++ Crypto Library

- [Generate Keys](#generate-keys)
- [Encrypt and Decrypt data](#encrypt-and-decrypt-data)
  - [Encrypt and Decrypt data using password](#encrypt-and-decrypt-data-using-password)
  - [Encrypt and Decrypt data using Key](#encrypt-and-decrypt-data-using-key)
  - [Encrypt data for multiple recipients](#encrypt-data-for-multiple-recipients)
- [Sign and Verify data](#sign-and-verify-data)
  
## Generate Keys
```cpp
// Specify password in the constructor to store private key encrypted.
// VirgilByteArray pwd = virgil::crypto::str2bytes("strong private key password");
// VirgilKeyPair newKeyPair(pwd);

VirgilKeyPair newKeyPair;
VirgilByteArray publicKey = newKeyPair.publicKey();
VirgilByteArray privateKey = newKeyPair.privateKey();
```
See full example [here.](https://github.com/VladEvka/virgil-sdk-cpp/blob/develop/examples/src/keygen.cxx)


## Encrypt and Decrypt data

### Encrypt and Decrypt data using password

#### Encrypt data
```cpp
VirgilStreamCipher cipher;
VirgilByteArray recipientPass = virgil::crypto::str2bytes("strong password");
cipher.addPasswordRecipient(recipientPass);
cipher.encrypt(dataSource, dataSink, true);
```
See full example [here.]()

#### Decrypt data
```cpp
VirgilStreamCipher cipher;
VirgilByteArray recipientPass = virgil::crypto::str2bytes("strong password");
cipher.decryptWithPassword(dataSource, dataSink, recipientPass);
```
See full example [here.]()

## Encrypt and Decrypt data using Key
### Encrypt data
```cpp
VirgilStreamCipher cipher;
cipher.addKeyRecipient(publicKeyId, publicKey.key());
cipher.encrypt(dataSource, dataSink, true);
```
See full example [here.]()

### Decrypt data
```cpp
VirgilStreamCipher cipher;
// using private key with password
// cipher.decryptWithKey(dataSource, dataSink, publicKeyId, privateKey, privateKeyPass);
cipher.decryptWithKey(dataSource, dataSink, publicKeyId, privateKey);
```
See full example [here.]()


## Encrypt data for multiple recipients
```cpp
VirgilStreamCipher cipher;
cipher.addKeyRecipient(alicePublicKeyId, alicePublicKey.key());
cipher.addKeyRecipient(bobPublicKeyId, bobPublicKey.key());
VirgilByteArray recipientPass = virgil::crypto::str2bytes("strong password");
cipher.addPasswordRecipient(recipientPass);
cipher.encrypt(dataSource, dataSink, true);
```
See full example [here.]()

## Sign and Verify data

### Sign data
```cpp
VirgilStreamSigner signer;
// if Signer has a private key with password
// std::string privateKeyPass = "strong private key password";
// VirgilByteArray sign = signer.sign(dataSource, privateKey, privateKeyPass);
VirgilByteArray sign = signer.sign(dataSource, privateKey);
```

### Verify data
```cpp
VirgilStreamSigner signer;
bool verified = signer.verify(dataSource, sign, publicKey.key());
```
See full example [here.]()
