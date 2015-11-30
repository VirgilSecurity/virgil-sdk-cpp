# C++ Keys Service

- [Obtaining an Application Token](#obtaining-an-application-token)
- [Register a New User](#register-a-new-user)
- [Get a User's Public Key](#get-a-users-public-key)
- [Search Public Key Data](#search-public-key-data)
- [Search Public Key Signed Data](#search-public-key-signed-data)
- [Update Public Key Data](#update-public-key-data)
- [Delete Public Key Data](#delete-public-key-data)
- [Reset a Public Key](#reset-a-public-key)
- [Confirm a Public Key delete operation](#confirm-a-Public-Key-delete-operation)
- [Confirm a Public Key reset operation](#confirm-a-Public-Key-reset-operation)
- [Create Public Key User Data](#create-public-key-user-data)
- [Delete User Data from the Public Key](#delete-user-data-from-the-public-key)
- [Confirm User Data](#confirm-user-data)
- [Resend a User's Confirmation Code](#resend-a-users-confirmation-code)

## Obtaining an Application Token

First you must create a free Virgil Security developer account by signing up [here](https://virgilsecurity.com/signup). Once you have your account you can [sign in](https://virgilsecurity.com/signin) and generate an app token for your application.

The app token provides authenticated secure access to Virgil’s Keys Service and is passed with each API call. The app token also allows the API to associate your app’s requests with your Virgil Security developer account.

Simply add your app token to the HTTP header for each request:

```
X-VIRGIL-APPLICATION-TOKEN: <YOUR_APPLICATION_TOKEN>
```

> Before using the services you have to obtain the Virgil Security Application Token, please follow the [Obtaining an Application Token](#obtaining-an-application-token) section above.

## Register a New User

> A Virgil Account will be created when the first Public Key is uploaded. An application can only get information about Public Keys created for the current application. When the application uploads a new Public Key and there is an Account created for another application with the same UDID, the Public Key will be implicitly attached it to the existing Account instance.

> Once you've created a public key you may push it to Virgil’s Keys Service. This will allow other users to send you encrypted data using your public key.

```cpp
UserData userData = UserData::email("mail@server.com");
Credentials credentials(privateKey);
KeysClient keysClient("{Application Token}");
PublicKey virgilPublicKey = keysClient.publicKey().add(publicKey, {userData}, credentials);
```
See full example [here.]()
>If registration successfull confirmation code will be sent to the user email.
To confirm, you must use - [Confirm User Data.](#confirm-user-data)


## Get a User's Public Key

```cpp
KeysClient keysClient("{Application Token}");
PublicKey publicKey = keysClient.publicKey().get(publicKeyId);
```
See full example [here.]()


## Search Public Key Data

```cpp
KeysClient keysClient("{Application Token}");
PublicKey publicKey = keysClient.publicKey().grab("mail@server.com");
```
See full example [here.]()


## Search Public Key Signed Data

> If a signed version of the action is used, the Public Key will be returned with all of the user_data items for this Public Key. Where:

```cpp
CredentialsExt credentialsExt(publicKeyId, privateKey);
KeysClient keysClient("{Application Token}");
PublicKey publicKey = keysClient.publicKey().grab(credentialsExt);
```
See full example [here.]()


## Update Public Key Data

> Public Key modification takes place immediately after action invocation.

```cpp
Credentials newKeyCredentials(newPrivateKey);
CredentialsExt oldKeyCredentialsExt(oldPublicKey.publicKeyId(), oldPrivateKey);

KeysClient keysClient("{Application Token}");
keysClient.publicKey().update(newPublicKey, newKeyCredentials, oldKeyCredentialsExt);
```
See full example [here.]()


## Delete Public Key Data

> If a signed version of the action is used, the Public Key will be removed immediately without any confirmation.
  
> If an unsigned version of the action is used, confirmation is required. 
> The action will return an action_token response object and will send confirmation tokens to all of the Public Key’s confirmed UDIDs. 
> The list of masked UDID’s will be returned in user_ids response object property. 
> To commit a Public Key remove call [Confirm a Public Key delete operation](#confirm-a-Public-Key-delete-operation) action with action_token value and the list of confirmation codes.

### Unsigned version
```cpp
KeysClient keysClient("{Application Token}");
std::string confirmInfo = keysClient.publicKey().del(publicKey.publicKeyId());
```
See full example [here.]()

### Signed version
```cpp
CredentialsExt credentialsExt(publicKey.publicKeyId(), privateKey);
KeysClient keysClient("{Application Token}");
keysClient.publicKey().del(credentialsExt);
```
See full example [here.]()


## Reset a Public Key

> After action invocation the user will receive the confirmation tokens on all his confirmed UDIDs. 
> The Public Key data won’t be updated until the call [Confirm a Public Key reset operation](#confirm-a-Public-Key-reset-operation) is invoked with the token value from this step and confirmation codes sent to UDIDs. 
> The list of UDIDs used as confirmation tokens recipients will be listed as user_ids response parameters.

```cpp
Credentials newKeyCredentials(newPrivateKey);
KeysClient keysClient("{Application Token}");
std::string confirmInfo = keysClient.publicKey().reset(oldPublicKey.publicKeyId(),
	    newPublicKey, newKeyCredentials);
```
See full example [here.]()


## Confirm a Public Key reset operation
> Send confirmation code to the Virgil Keys service to finish Public Key reset operation.

```cpp
KeysClient keysClient("{Application Token}");
Credentials credentials(privateKey);
keysClient.publicKey().confirmReset(oldPublicKey.publicKeyId(), credentials,
		<action_token>, {<confirmation_codes>});
```
See full example [here.]()


## Confirm a Public Key delete operation
> Send confirmation code to the Virgil Keys service to finish Public Key delete operation.

```cpp
KeysClient keysClient("{Application Token}");
keysClient.publicKey().confirmDel(publicKey.publicKeyId(),
		<action_token>, {<confirmation_codes>});
```
See full example [here.]()


## Create Public Key User Data

> Add user data, i.e. email. If registration successfull confirmation code will be sent to the user.
To confirm user data use [Confirm User Data](#confirm-user-data).

```cpp
KeysClient keysClient("{Application Token}");
UserData userData = UserData::email("newmail@server.com");
CredentialsExt credentialsExt(publicKey.publicKeyId(), privateKey);
UserData userDataResponse = keysClient.userData().add(userData, credentialsExt);
```
See full example [here.]()


## Delete User Data from the Public Key
> Remove user data item from the associated Public Key.

```cpp
KeysClient keysClient("{Application Token}");
CredentialsExt credentialsExt(publicKey.publicKeyId(), privateKey);
keysClient.userData().del(<user_data_id>, credentialsExt);
```
See full example [here.]()


## Confirm User Data
> Send confirmation code to the Virgil Keys service.
Confirmation code provided for user after:

  * [Create Public Key User Data](#create-public-key-user-data);
  * [Register a New User](#register-a-new-user)

```cpp
KeysClient keysClient("{Application Token}");
keysClient.userData().confirm(<user_data_id>, <confirmation_code>);
```
See full example [here.]()

## Resend a User's Confirmation Code
> Resend confirmation code to the user for given user's identifier.

```cpp
KeysClient keysClient("{Application Token}");
CredentialsExt credentialsExt(publicKey.publicKeyId(), privateKey);
keysClient.userData().resendConfirmation(<user_data_id>, credentialsExt);
```
See full example [here.]()
