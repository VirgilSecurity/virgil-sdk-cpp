# С++ Private Keys Service

- [Obtaining an Application Token](#obtaining-an-application-token)
- [Create a New Container Object](#create-a-new-container-object)
- [Authenticate Session](#authenticate-session)
- [Get Container Object](#get-container-object)
- [Delete Container Object](#delete-container-object)
- [Update Container Object](#update-container-object)
- [Reset Container Password](#reset-container-password)
- [Persist Container Object](#persist-container-object)
- [Create a Private Key inside the Container Object](#create-a-private-key-inside-the-container-object)
- [Get Private Key Object](#get-private-key-object)
- [Delete Private Key Object](#delete-private-key-object)


## Obtaining an Application Token

First you must create a free Virgil Security developer account by signing up [here](https://virgilsecurity.com/signup). Once you have your account you can [sign in](https://virgilsecurity.com/signin) and generate an app token for your application.

The app token provides authenticated secure access to Virgil’s Keys Service and is passed with each API call. The app token also allows the API to associate your app’s requests with your Virgil Security developer account.

Simply add your app token to the HTTP header for each request:

```
X-VIRGIL-APPLICATION-TOKEN: <YOUR_APPLICATION_TOKEN>
```

> Create an Application under [Virgil Security, Inc](https://virgilsecurity.com/dashboard).

> Obtain the Virgil Security Application Token, please follow the [Obtaining an Application Token](#obtaining-an-application-token) section above.

> Create Private and Public Keys on your local machine.

> Create and confirm your account in the Public Keys service.

> Load a Public Key to the Public Key service.

> Use the same email that you used for the Public Key service.


## Create a New Container Object

> Create container for storing Private Keys on the Virgil Private Keys Service.
Container type:
>  * `easy` - instructs Private Keys Service to use container's password for Private Keys encryption, so it can be reset if user forget it.
>  * `normal` - instructs Private Keys Service not to use container's password for Private Keys encryption, so user is responsible for Private Key password, and it can not be reset within Virgil Private Keys Service.

```cpp
PrivateKeysClient privateKeysClient("{Application Token}");
CredentialsExt credentialsExt(publicKeyId, privateKey);
ContainerType CONTAINER_TYPE = ContainerType::Easy;
std::string CONTAINER_PASSWORD = "123456789";
privateKeysClient.container().create(credentialsExt, CONTAINER_TYPE, CONTAINER_PASSWORD);
```
See full example [here.](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/develop/examples/src/container_create.cxx)


## Authenticate Session

Service will create **`Authentication token`** that will be available during the 60 minutes after creation. During this time service will automatically prolong life time of the token in case if **`Authentication token`** widely used so don't need to prolong it manually. In case when **`Authentication token`** is used after 60 minutes of life time, service will throw the appropriate error.

> Note:
 Before login make sure that you have already [created Container Object](#create-a-new-container-object) under Private Key service. Use for user_data.value parameter the same value as you have registered under Public Keys service. This account has to be confirmed under Public Key service.

In the **`Authentication token`** need to the following endpoints:

1. [Get Container Object](#get-container-objec)
1. [Delete Container Object](#delete-container-object)
1. [Update Container Object](#update-container-object)
1. [Create a Private Key inside the Container Object](#create-a-private-key-inside-the-container-object)
1. [Get Private Key Object](#get-private-key-object)
1. [Delete Private Key Object](#delete-private-key-object)

```cpp
PrivateKeysClient privateKeysClient("{Application Token}");
UserData userData = UserData::email(USER_EMAIL);
std::string authenticationToken = privateKeysClient.auth().getAuthToken(userData, CONTAINER_PASSWORD);
```
See full example [here.](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/develop/examples/src/authenticate.cxx)


## Get Container Object

Get container type. It can be `easy` or `normal`.

```cpp
PrivateKeysClient privateKeysClient("{Application Token}");
UserData userData = UserData::email(USER_EMAIL);
privateKeysClient.authenticate(userData, CONTAINER_PASSWORD);

// if the token has been received
// std::string authenticationToken = "";
// privateKeysClient.authenticate(authenticationToken);  

ContainerType containerType = privateKeysClient.container().getDetails(publicKeyId);
```
See full example [here.](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/develop/examples/src/container_info_get.cxx)


## Delete Container Object

Delete existing container from the Virgil Private Key service.

```cpp
PrivateKeysClient privateKeysClient("{Application Token}");
UserData userData = UserData::email(USER_EMAIL);
privateKeysClient.authenticate(userData, CONTAINER_PASSWORD);

// if the token has been received
// std::string authenticationToken = "";
// privateKeysClient.authenticate(authenticationToken);

CredentialsExt credentialsExt(publicKeyId, privateKey);
privateKeysClient.container().del(credentialsExt);
```
See full example [here.](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/develop/examples/src/container_delete.cxx)


## Update Container Object

By invoking this method you can change the Container Password

```cpp
PrivateKeysClient privateKeysClient("{Application Token}");
UserData userData = UserData::email(USER_EMAIL);
privateKeysClient.authenticate(userData, CONTAINER_PASSWORD);

// if the token has been received
// std::string authenticationToken = "";
// privateKeysClient.authenticate(authenticationToken);

CredentialsExt credentialsExt(publicKey.publicKeyId(), privateKey);
privateKeysClient.container().update(credentials, CONTAINER_NEW_PASSWORD);
```
See full example [here.](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/develop/examples/src/container_update.cxx)


## Reset Container Password

A user can reset their Private Key object password if the Container Type equals `easy`. 
If the Container Type equals `normal`, the Private Key object will be stored in its original form.

```cpp
PrivateKeysClient privateKeysClient("{Application Token}");
UserData userData = UserData::email(USER_EMAIL);
privateKeysClient.container().resetPassword(userData, CONTAINER_NEW_PASSWORD);
```
See full example [here.](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/develop/examples/src/container_reset_password.cxx)


## Persist Container Object

Confirm password reset action and re-encrypt Private Key data with the new password if 
container type is `easy`.

> The token generated during the container reset invocation only lives for 60 minutes.

```cpp
PrivateKeysClient privateKeysClient("{Application Token}");
privateKeysClient.container().confirm(<confirmation_token>);
```
See full example [here.](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/develop/examples/src/container_confirm.cxx)


## Create a Private Key inside the Container Object

Load an existing Private Key into the Private Keys service and associate it with the existing Container object.

> Prerequisite:

> 1. Create container, see [Create a New Container Object](#create-a-new-container-object).
> 1. Get authentication token, see [Authenticate Session.](#authenticate-session)

```cpp
PrivateKeysClient privateKeysClient("{Application Token}");
UserData userData = UserData::email(USER_EMAIL);
privateKeysClient.authenticate(userData, CONTAINER_PASSWORD);

// if the token has been received
// std::string authenticationToken = "";
// privateKeysClient.authenticate(authenticationToken);

CredentialsExt credentials(publicKeyId, privateKey);
privateKeysClient.privateKey().add(credentials, CONTAINER_PASSWORD);
```
See full example [here.](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/develop/examples/src/private_key_add.cxx)


## Get Private Key Object

> Get user's Private Key from the Virgil Private Keys service.

```cpp
PrivateKeysClient privateKeysClient("{Application Token}");
UserData userData = UserData::email(USER_EMAIL);
privateKeysClient.authenticate(userData, CONTAINER_PASSWORD);

// if the token has been received
// std::string authenticationToken = "";
// privateKeysClient.authenticate(authenticationToken);

PrivateKey privateKey = privateKeysClient.privateKey().get(publicKeyId, CONTAINER_PASSWORD);
```
See full example [here.](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/develop/examples/src/private_key_get.cxx)


## Delete Private Key Object

> Delete a Private Key object. A Private Key object will be disconnected from the Container Object and then deleted from the Private Key service.

```cpp
PrivateKeysClient privateKeysClient("{Application Token}");
UserData userData = UserData::email(USER_EMAIL);
privateKeysClient.authenticate(userData, CONTAINER_PASSWORD);

// if the token has been received
// std::string authenticationToken = "";
// privateKeysClient.authenticate(authenticationToken);

CredentialsExt credentialsExt(publicKey.publicKeyId(), privateKey);
privateKeysClient.container().del(credentialsExt);
```
See full example [here.](https://github.com/VirgilSecurity/virgil-sdk-cpp/blob/develop/examples/src/private_key_delete.cxx)