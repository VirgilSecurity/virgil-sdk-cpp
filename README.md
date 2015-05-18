# Virgil Security C++ library

- [Introduction](#introduction)
- [Build prerequisite](#build-prerequisite)
- [Build](#build)
- [Examples](#examples)
    - [General statements](#general-statements)
    - [Example 1: Generate keys](#example-1)
    - [Example 2: Register user on the PKI service](#example-2)
    - [Example 3: Get user's public key from the PKI service](#example-3)
    - [Example 4: Encrypt data](#example-4)
    - [Example 5: Decrypt data](#example-5)
    - [Example 6: Sign data](#example-6)
    - [Example 7: Verify data](#example-7)
- [License](#license)
- [Contacts](#contacts)

## Introduction

This branch focuses on the C++ library implementation and covers next topics:

  * build prerequisite;
  * build;
  * usage exmaples.

Common library description can be found [here](https://github.com/VirgilSecurity/virgil).

## Build prerequisite

1. [CMake](http://www.cmake.org/).
1. [Git](http://git-scm.com/).
1. [Python](http://python.org/).
1. [Python YAML](http://pyyaml.org/).
1. C/C++ compiler:
    [gcc](https://gcc.gnu.org/),
    [clang](http://clang.llvm.org/),
    [MinGW](http://www.mingw.org/),
    [Microsoft Visual Studio](http://www.visualstudio.com/), or other.
1. [libcurl](http://curl.haxx.se/libcurl/).

## Build

1. Run one of the folowing scripts:

    * build.sh - on the Unix-like OS;
    * build.bat - on the Windows OS [coming soon].

1. Inspect folder `origin_lib` that contains built library.

1. Inspect folder `examples_bin` that contains built examples.

## Examples

This section describes common case library usage scenarios, like

- generate new keys;
- register user on the Virgil PKI service;
- encrypt data for user identified by email, phone, etc;
- decrypt data with private key;
- sign data with private key;
- verify data with signer identified by email, phone, etc.

### General statements

1. Examples MUST be run from their directory.
1. All results are stored in the same directory.
1. To produce file `virgil_public.key` run:
    - `get_public_key` - if user is registered;
    - `register_user` - if user is not registered.
1. To produce `test.txt.sign` run `sign`.
1. To produce `text.txt.enc` run `encrypt`.
1. To produce `decrypted_text.txt` run `decrypt`.

### <a name="example-1"></a> Example 1: Generate keys

*Output*:

- Public Key, write to file `new_public.key`

- Private Key, write to file `new_private.key`

``` {.cpp}
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>
#include <stdexcept>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;
#include <virgil/service/data/VirgilKeyPair.h>
using virgil::service::data::VirgilKeyPair;

int main(int argc, char **argv) {
    try {
        std::cout << "Generate keys with with password: 'password'" << std::endl;
        VirgilKeyPair newKeyPair(virgil::str2bytes("password"));

        std::cout << "Store public key: new_public.key ..." << std::endl;
        std::ofstream publicKeyStream("new_public.key", std::ios::out | std::ios::binary);
        if (!publicKeyStream.good()) {
            throw std::runtime_error("can not write file: new_public.key");
        }
        VirgilByteArray publicKey = newKeyPair.publicKey();
        std::copy(publicKey.begin(), publicKey.end(), std::ostreambuf_iterator<char>(publicKeyStream));

        std::cout << "Store private key: new_private.key ..." << std::endl;
        std::ofstream privateKeyStream("new_private.key", std::ios::out | std::ios::binary);
        if (!privateKeyStream.good()) {
            throw std::runtime_error("can not write file: new_private.key");
        }
        VirgilByteArray privateKey = newKeyPair.privateKey();
        std::copy(privateKey.begin(), privateKey.end(), std::ostreambuf_iterator<char>(privateKeyStream));
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
    }
    return 0;
}
```

### <a name="example-2"></a> Example 2: Register user on the PKI service

*Input*:

- User ID, hardcoded to `test.virgilsecurity@mailinator.com`

*Output*:

- Virgil Public Key, write to file `virgil_public.key`

``` {.cpp}
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>
#include <stdexcept>
#include <map>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;
#include <virgil/VirgilException.h>
using virgil::VirgilException;
#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;
#include <virgil/crypto/VirgilBase64.h>
using virgil::crypto::VirgilBase64;

#include <curl/curl.h>
#include <json/json.h>

#define VIRGIL_PKI_URL_BASE "https://pki.virgilsecurity.com/"
#define USER_ID_TYPE "email"
#define USER_ID "test.virgilsecurity@mailinator.com"

#define MAKE_URL(base, path) (base path)

static int pki_callback(char *data, size_t size, size_t nmemb, std::string *buffer_in) {
    // Is there anything in the buffer?
    if (buffer_in != NULL) {
        // Append the data to the buffer
        buffer_in->append(data, size * nmemb);
        return size * nmemb;
    }
    return 0;
}

static std::string pki_post(const std::string& url, const std::string& json) {
    CURL *curl = NULL;
    CURLcode result = CURLE_OK;
    struct curl_slist *headers = NULL;
    std::string response;

    /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);

    /* get a curl handle */
    curl = curl_easy_init();
    if (curl) {
        /* set content type */
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        /* Set the URL */
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        /* Now specify the POST data */
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, json.c_str());

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, pki_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)(&response));

        /* Perform the request, result will get the return code */
        result = curl_easy_perform(curl);

        /* free headers */
        curl_slist_free_all(headers);

        /* cleanup curl handle */
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    /* Check for errors */
    if (result == CURLE_OK) {
        return response;
    } else {
        throw std::runtime_error(std::string("cURL failed with error: ") + curl_easy_strerror(result));
    }
}

VirgilCertificate
pki_create_user(const VirgilByteArray& publicKey, const std::map<std::string, std::string>& ids) {
    // Create request
    Json::Value payload;
    payload["public_key"] = VirgilBase64::encode(publicKey);
    Json::Value userData(Json::arrayValue);
    for (std::map<std::string, std::string>::const_iterator id = ids.begin(); id != ids.end(); ++id) {
        Json::Value data(Json::objectValue);
        data["class"] = "user_id";
        data["type"] = id->first;
        data["value"] = id->second;
        userData.append(data);
    }
    payload["user_data"] = userData;
    // Perform request
    std::string response = pki_post(MAKE_URL(VIRGIL_PKI_URL_BASE, "objects/public-key"),
            Json::FastWriter().write(payload));
    // Parse response
    Json::Reader reader(Json::Features::strictMode());
    Json::Value responseObject;
    if (!reader.parse(response, responseObject)) {
        throw VirgilException(reader.getFormattedErrorMessages());
    }
    const Json::Value& accountIdObject = responseObject["id"]["account_id"];
    const Json::Value& publicKeyIdObject = responseObject["id"]["public_key_id"];

    if (accountIdObject.isString() && publicKeyIdObject.isString()) {
        VirgilCertificate virgilPublicKey(publicKey);
        virgilPublicKey.id().setAccountId(virgil::str2bytes(accountIdObject.asString()));
        virgilPublicKey.id().setCertificateId(virgil::str2bytes(publicKeyIdObject.asString()));
        return virgilPublicKey;
    } else {
        throw std::runtime_error(std::string("Unexpected response format:\n") + responseObject.toStyledString());
    }
}

int main() {
    try {
        std::cout << "Prepare input file: public.key..." << std::endl;
        std::ifstream inFile("public.key", std::ios::in | std::ios::binary);
        if (!inFile.good()) {
            throw std::runtime_error("can not read file: public.key");
        }

        std::cout << "Prepare output file: virgil_public.key..." << std::endl;
        std::ofstream outFile("virgil_public.key", std::ios::out | std::ios::binary);
        if (!outFile.good()) {
            throw std::runtime_error("can not write file: virgil_public.key");
        }

        std::cout << "Read public key..." << std::endl;
        VirgilByteArray publicKey;
        std::copy(std::istreambuf_iterator<char>(inFile), std::istreambuf_iterator<char>(),
                std::back_inserter(publicKey));

        std::cout << "Create user (" << USER_ID << ") account on the Virgil PKI service..." << std::endl;
        std::map<std::string, std::string> userIds;
        userIds[USER_ID_TYPE] = USER_ID;
        VirgilCertificate virgilPublicKey = pki_create_user(publicKey, userIds);

        std::cout << "Store virgil public key to the output file..." << std::endl;
        VirgilByteArray virgilPublicKeyData = virgilPublicKey.toAsn1();
        std::copy(virgilPublicKeyData.begin(), virgilPublicKeyData.end(), std::ostreambuf_iterator<char>(outFile));
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
    }
    return 0;
}
```

### <a name="example-3"></a> Example 3: Get user's public key from the PKI service

*Input*:

- User ID, hardcoded to `test.virgilsecurity@mailinator.com`

*Output*:

- Virgil Public Key, write to file `virgil_public.key`

``` {.cpp}
#include <cstddef>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>
#include <stdexcept>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;
#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;
#include <virgil/crypto/VirgilBase64.h>
using virgil::crypto::VirgilBase64;

#include <curl/curl.h>
#include <json/json.h>

#define VIRGIL_PKI_URL_BASE "https://pki.virgilsecurity.com/"
#define USER_ID_TYPE "email"
#define USER_ID "test.virgilsecurity@mailinator.com"

#define MAKE_URL(base, path) (base path)

static int pki_callback(char *data, size_t size, size_t nmemb, std::string *buffer_in) {
    // Is there anything in the buffer?
    if (buffer_in != NULL) {
        // Append the data to the buffer
        buffer_in->append(data, size * nmemb);
        return size * nmemb;
    }
    return 0;
}

static std::string pki_post(const std::string& url, const std::string& json) {
    CURL *curl = NULL;
    CURLcode result = CURLE_OK;
    struct curl_slist *headers = NULL;
    std::string response;

    /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);

    /* get a curl handle */
    curl = curl_easy_init();
    if (curl) {
        /* set content type */
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        /* Set the URL */
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        /* Now specify the POST data */
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, json.c_str());

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, pki_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)(&response));

        /* Perform the request, result will get the return code */
        result = curl_easy_perform(curl);

        /* free headers */
        curl_slist_free_all(headers);

        /* cleanup curl handle */
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    /* Check for errors */
    if (result == CURLE_OK) {
        return response;
    } else {
        throw std::runtime_error(std::string("cURL failed with error: ") + curl_easy_strerror(result));
    }
}

VirgilCertificate pki_get_public_key(const std::string& userIdType, const std::string& userId) {
    // Create request
    Json::Value payload;
    payload[userIdType] = userId;
    // Perform request
    std::string response = pki_post(MAKE_URL(VIRGIL_PKI_URL_BASE, "objects/account/actions/search"),
            Json::FastWriter().write(payload));
    // Parse response
    Json::Reader reader(Json::Features::strictMode());
    Json::Value responseObject;
    if (!reader.parse(response, responseObject)) {
        throw std::runtime_error(reader.getFormattedErrorMessages());
    }
    const Json::Value& virgilPublicKeyObject = responseObject[0]["public_keys"][0];
    const Json::Value& idObject = virgilPublicKeyObject["id"]["public_key_id"];
    const Json::Value& publicKeyObject = virgilPublicKeyObject["public_key"];

    if (idObject.isString() && publicKeyObject.isString()) {
        VirgilCertificate virgilPublicKey(VirgilBase64::decode(publicKeyObject.asString()));
        virgilPublicKey.id().setCertificateId(virgil::str2bytes(idObject.asString()));
        return virgilPublicKey;
    } else {
        throw std::runtime_error(std::string("virgil public key for recipient '") + userId +
                "' of type '" + userIdType + "' not found");
    }
}

int main() {
    try {
        std::cout << "Get user ("<< USER_ID << ") information from the Virgil PKI service..." << std::endl;
        VirgilCertificate virgilPublicKey = pki_get_public_key(USER_ID_TYPE, USER_ID);

        std::cout << "Prepare output file: virgil_public.key..." << std::endl;
        std::ofstream outFile("virgil_public.key", std::ios::out | std::ios::binary);
        if (!outFile.good()) {
            throw std::runtime_error("can not write file: virgil_public.key");
        }

        std::cout << "Store virgil public key to the output file..." << std::endl;
        VirgilByteArray virgilPublicKeyData = virgilPublicKey.toAsn1();
        std::copy(virgilPublicKeyData.begin(), virgilPublicKeyData.end(), std::ostreambuf_iterator<char>(outFile));
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
    }
    return 0;
}
```

### <a name="example-4"></a> Example 4: Encrypt data

*Input*:

- User ID, hardcoded to `test.virgilsecurity@mailinator.com`
- Data, read from file `text.txt`

*Output*:

- Encrypted data, write to file `text.txt.enc`

``` {.cpp}
#include <cstddef>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>
#include <stdexcept>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;
#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;
#include <virgil/service/VirgilStreamCipher.h>
using virgil::service::VirgilStreamCipher;
#include <virgil/stream/VirgilStreamDataSource.h>
using virgil::stream::VirgilStreamDataSource;
#include <virgil/stream/VirgilStreamDataSink.h>
using virgil::stream::VirgilStreamDataSink;
#include <virgil/crypto/VirgilBase64.h>
using virgil::crypto::VirgilBase64;

#include <curl/curl.h>
#include <json/json.h>

#define VIRGIL_PKI_URL_BASE "https://pki.virgilsecurity.com/"
#define USER_ID_TYPE "email"
#define USER_ID "test.virgilsecurity@mailinator.com"

#define MAKE_URL(base, path) (base path)

static int pki_callback(char *data, size_t size, size_t nmemb, std::string *buffer_in) {
    // Is there anything in the buffer?
    if (buffer_in != NULL) {
        // Append the data to the buffer
        buffer_in->append(data, size * nmemb);
        return size * nmemb;
    }
    return 0;
}

static std::string pki_post(const std::string& url, const std::string& json) {
    CURL *curl = NULL;
    CURLcode result = CURLE_OK;
    struct curl_slist *headers = NULL;
    std::string response;

    /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);

    /* get a curl handle */
    curl = curl_easy_init();
    if (curl) {
        /* set content type */
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        /* Set the URL */
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        /* Now specify the POST data */
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, json.c_str());

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, pki_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)(&response));

        /* Perform the request, result will get the return code */
        result = curl_easy_perform(curl);

        /* free headers */
        curl_slist_free_all(headers);

        /* cleanup curl handle */
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    /* Check for errors */
    if (result == CURLE_OK) {
        return response;
    } else {
        throw std::runtime_error(std::string("cURL failed with error: ") + curl_easy_strerror(result));
    }
}

VirgilCertificate pki_get_public_key(const std::string& userIdType, const std::string& userId) {
    // Create request
    Json::Value payload;
    payload[userIdType] = userId;
    // Perform request
    std::string response = pki_post(MAKE_URL(VIRGIL_PKI_URL_BASE, "objects/account/actions/search"),
            Json::FastWriter().write(payload));
    // Parse response
    Json::Reader reader(Json::Features::strictMode());
    Json::Value responseObject;
    if (!reader.parse(response, responseObject)) {
        throw std::runtime_error(reader.getFormattedErrorMessages());
    }
    const Json::Value& virgilPublicKeyObject = responseObject[0]["public_keys"][0];
    const Json::Value& idObject = virgilPublicKeyObject["id"]["public_key_id"];
    const Json::Value& publicKeyObject = virgilPublicKeyObject["public_key"];

    if (idObject.isString() && publicKeyObject.isString()) {
        VirgilCertificate virgilPublicKey(VirgilBase64::decode(publicKeyObject.asString()));
        virgilPublicKey.id().setCertificateId(virgil::str2bytes(idObject.asString()));
        return virgilPublicKey;
    } else {
        throw std::runtime_error(std::string("virgil public key for recipient '") + userId +
                "' of type '" + userIdType + "' not found");
    }
}

int main() {
    try {
        std::cout << "Prepare input file: test.txt..." << std::endl;
        std::ifstream inFile("test.txt", std::ios::in | std::ios::binary);
        if (!inFile.good()) {
            throw std::runtime_error("can not read file: test.txt");
        }

        std::cout << "Prepare output file: test.txt.enc..." << std::endl;
        std::ofstream outFile("test.txt.enc", std::ios::out | std::ios::binary);
        if (!outFile.good()) {
            throw std::runtime_error("can not write file: test.txt.enc");
        }

        std::cout << "Initialize cipher..." << std::endl;
        VirgilStreamCipher cipher;

        std::cout << "Get recipient ("<< USER_ID << ") information from the Virgil PKI service..." << std::endl;
        VirgilCertificate virgilPublicKey = pki_get_public_key(USER_ID_TYPE, USER_ID);
        std::cout << "Add recipient..." << std::endl;
        cipher.addKeyRecipient(virgilPublicKey.id().certificateId(), virgilPublicKey.publicKey());

        std::cout << "Encrypt and store results..." << std::endl;
        VirgilStreamDataSource dataSource(inFile);
        VirgilStreamDataSink dataSink(outFile);
        cipher.encrypt(dataSource, dataSink, true);

        std::cout << "Encrypted data is successfully stored in the output file..." << std::endl;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
    }
    return 0;
}
```

### <a name="example-5"></a> Example 5: Decrypt data

*Input*:

- Encrypted data, read from file `text.txt.enc`
- Virgil Public Key, read from file `virgil_public.key`
- Private Key, read from file `private.key`
- Private Key password, hardcoded to `password`

*Output*:

- Decrypted data, write to file `decrypted_text.txt`

``` {.cpp}
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>
#include <stdexcept>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;
#include <virgil/VirgilException.h>
using virgil::VirgilException;
#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;
#include <virgil/service/VirgilStreamCipher.h>
using virgil::service::VirgilStreamCipher;
#include <virgil/stream/VirgilStreamDataSource.h>
using virgil::stream::VirgilStreamDataSource;
#include <virgil/stream/VirgilStreamDataSink.h>
using virgil::stream::VirgilStreamDataSink;

#include <virgil/stream/utils.h>

int main() {
    try {
        std::cout << "Prepare input file: test.txt.enc..." << std::endl;
        std::ifstream inFile("test.txt.enc", std::ios::in | std::ios::binary);
        if (!inFile.good()) {
            throw std::runtime_error("can not read file: test.txt.enc");
        }

        std::cout << "Prepare output file: decrypted_test.txt..." << std::endl;
        std::ofstream outFile("decrypted_test.txt", std::ios::out | std::ios::binary);
        if (!outFile.good()) {
            throw std::runtime_error("can not write file: decrypted_test.txt");
        }

        std::cout << "Initialize cipher..." << std::endl;
        VirgilStreamCipher cipher;

        std::cout << "Read virgil public key..." << std::endl;
        VirgilCertificate virgilPublicKey = virgil::stream::read_certificate("virgil_public.key");

        std::cout << "Read private key..." << std::endl;
        std::ifstream keyFile("private.key", std::ios::in | std::ios::binary);
        if (!keyFile.good()) {
            throw std::runtime_error("can not read private key: private.key");
        }
        VirgilByteArray privateKey;
        std::copy(std::istreambuf_iterator<char>(keyFile), std::istreambuf_iterator<char>(),
                std::back_inserter(privateKey));
        VirgilByteArray privateKeyPassword = virgil::str2bytes("password");

        std::cout << "Decrypt..." << std::endl;
        VirgilStreamDataSource dataSource(inFile);
        VirgilStreamDataSink dataSink(outFile);
        cipher.decryptWithKey(dataSource, dataSink, virgilPublicKey.id().certificateId(),
                privateKey, privateKeyPassword);
        std::cout << "Decrypted data is successfully stored in the output file..." << std::endl;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
    }
    return 0;
}
```

### <a name="example-6"></a> Example 6: Sign data

*Input*:

- Data, read from file `text.txt`
- Virgil Public Key, read from file `virgil_public.key`
- Private Key, read from file `private.key`
- Private Key password, hardcoded to `password`

*Output*:

- Virgil Sign, write to file `test.txt.sign`

``` {.cpp}
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>
#include <stdexcept>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;
#include <virgil/service/VirgilStreamSigner.h>
using virgil::service::VirgilStreamSigner;
#include <virgil/stream/VirgilStreamDataSource.h>
using virgil::stream::VirgilStreamDataSource;
#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;
#include <virgil/stream/utils.h>

int main() {
    try {
        std::cout << "Prepare input file: test.txt..." << std::endl;
        std::ifstream inFile("test.txt", std::ios::in | std::ios::binary);
        if (!inFile.good()) {
            throw std::runtime_error("can not read file: test.txt");
        }

        std::cout << "Prepare output file: test.txt.sign..." << std::endl;
        std::ofstream outFile("test.txt.sign", std::ios::out | std::ios::binary);
        if (!outFile.good()) {
            throw std::runtime_error("can not write file: test.txt.sign");
        }

        std::cout << "Read virgil public key..." << std::endl;
        VirgilCertificate virgilPublicKey = virgil::stream::read_certificate("virgil_public.key");

        std::cout << "Read private key..." << std::endl;
        std::ifstream keyFile("private.key", std::ios::in | std::ios::binary);
        if (!keyFile.good()) {
            throw std::runtime_error("can not read private key: private.key");
        }
        VirgilByteArray privateKey;
        std::copy(std::istreambuf_iterator<char>(keyFile), std::istreambuf_iterator<char>(),
                std::back_inserter(privateKey));
        VirgilByteArray privateKeyPassword = virgil::str2bytes("password");

        std::cout << "Initialize signer..." << std::endl;
        VirgilStreamSigner signer;

        std::cout << "Sign data..." << std::endl;
        VirgilStreamDataSource dataSource(inFile);
        VirgilSign sign = signer.sign(dataSource, virgilPublicKey.id().certificateId(),
                privateKey, privateKeyPassword);

        std::cout << "Save sign..." << std::endl;
        VirgilByteArray signData = sign.toAsn1();
        std::copy(signData.begin(), signData.end(), std::ostreambuf_iterator<char>(outFile));

        std::cout << "Sign is successfully stored in the output file." << std::endl;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
    }
    return 0;
}
```

### <a name="example-7"></a> Example 7: Verify data

*Input*:

- Data, read from `text.txt`
- Virgil Sign, read from file `test.txt.sign`
- Signer ID, hardcoded to `test.virgilsecurity@mailinator.com`

*Output*:

- Verification result, print to the screen

``` {.cpp}
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>
#include <stdexcept>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;
#include <virgil/crypto/VirgilBase64.h>
using virgil::crypto::VirgilBase64;
#include <virgil/service/VirgilStreamSigner.h>
using virgil::service::VirgilStreamSigner;
#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;
#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;
#include <virgil/stream/VirgilStreamDataSource.h>
using virgil::stream::VirgilStreamDataSource;
#include <virgil/stream/utils.h>

#include <curl/curl.h>
#include <json/json.h>

#define VIRGIL_PKI_URL_BASE "https://pki.virgilsecurity.com/"
#define SIGNER_ID_TYPE "email"
#define SIGNER_ID "test.virgilsecurity@mailinator.com"

#define MAKE_URL(base, path) (base path)

static int pki_callback(char *data, size_t size, size_t nmemb, std::string *buffer_in) {
    // Is there anything in the buffer?
    if (buffer_in != NULL) {
        // Append the data to the buffer
        buffer_in->append(data, size * nmemb);
        return size * nmemb;
    }
    return 0;
}

static std::string pki_post(const std::string& url, const std::string& json) {
    CURL *curl = NULL;
    CURLcode result = CURLE_OK;
    struct curl_slist *headers = NULL;
    std::string response;

    /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);

    /* get a curl handle */
    curl = curl_easy_init();
    if (curl) {
        /* set content type */
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        /* Set the URL */
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        /* Now specify the POST data */
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, json.c_str());

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, pki_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)(&response));

        /* Perform the request, result will get the return code */
        result = curl_easy_perform(curl);

        /* free headers */
        curl_slist_free_all(headers);

        /* cleanup curl handle */
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    /* Check for errors */
    if (result == CURLE_OK) {
        return response;
    } else {
        throw std::runtime_error(std::string("cURL failed with error: ") + curl_easy_strerror(result));
    }
}

VirgilCertificate pki_get_public_key(const std::string& userIdType, const std::string& userId) {
    // Create request
    Json::Value payload;
    payload[userIdType] = userId;
    // Perform request
    std::string response = pki_post(MAKE_URL(VIRGIL_PKI_URL_BASE, "objects/account/actions/search"),
            Json::FastWriter().write(payload));
    // Parse response
    Json::Reader reader(Json::Features::strictMode());
    Json::Value responseObject;
    if (!reader.parse(response, responseObject)) {
        throw std::runtime_error(reader.getFormattedErrorMessages());
    }
    const Json::Value& virgilPublicKeyObject = responseObject[0]["public_keys"][0];
    const Json::Value& idObject = virgilPublicKeyObject["id"]["public_key_id"];
    const Json::Value& publicKeyObject = virgilPublicKeyObject["public_key"];

    if (idObject.isString() && publicKeyObject.isString()) {
        VirgilCertificate virgilPublicKey(VirgilBase64::decode(publicKeyObject.asString()));
        virgilPublicKey.id().setCertificateId(virgil::str2bytes(idObject.asString()));
        return virgilPublicKey;
    } else {
        throw std::runtime_error(std::string("virgil public key for recipient '") + userId +
                "' of type '" + userIdType + "' not found");
    }
}

int main() {
    try {
        std::cout << "Prepare input file: test.txt..." << std::endl;
        std::ifstream inFile("test.txt", std::ios::in | std::ios::binary);
        if (!inFile.good()) {
            throw std::runtime_error("can not read file: test.txt");
        }

        std::cout << "Read virgil sign..." << std::endl;
        VirgilSign virgilSign = virgil::stream::read_sign("test.txt.sign");

        std::cout << "Get signer ("<< SIGNER_ID << ") information from the Virgil PKI service..." << std::endl;
        VirgilCertificate virgilPublicKey = pki_get_public_key(SIGNER_ID_TYPE, SIGNER_ID);

        std::cout << "Initialize verifier..." << std::endl;
        VirgilStreamSigner signer;

        std::cout << "Verify data..." << std::endl;
        VirgilStreamDataSource dataSource(inFile);
        bool verified = signer.verify(dataSource, virgilSign, virgilPublicKey.publicKey());

        std::cout << "Data is " << (verified ? "" : "not ") << "verified!" << std::endl;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
    }
    return 0;
}
```

## License
BSD 3-Clause. See [LICENSE](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE) for details.

## Contacts
Email: <support@virgilsecurity.com>
