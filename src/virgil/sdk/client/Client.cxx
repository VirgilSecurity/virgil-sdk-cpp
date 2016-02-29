#include <virgil/sdk/client/Client.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilSigner.h>
#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/Credentials.h>
#include <virgil/sdk/models/CardModel.h>
#include <virgil/sdk/http/Response.h>
#include <virgil/sdk/http/Headers.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::str2bytes;
using virgil::crypto::VirgilSigner;
using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::Credentials;
using virgil::sdk::models::CardModel;
using virgil::sdk::client::Client;
using virgil::sdk::http::Response;

Client::Client(const std::string& accessToken, const std::string& baseServiceUri, CardProviderFunc cardProviderFunc)
        : accessToken_(accessToken),
          baseServiceUri_(baseServiceUri),
          cardProviderFunc_(cardProviderFunc),
          serviceCard_() {
}

std::string Client::getAccessToken() const {
    return accessToken_;
}

std::string Client::getBaseServiceUri() const {
    return baseServiceUri_;
}

CardModel Client::getServiceCard() const {
    if (!serviceCard_) {
        serviceCard_ = std::make_shared<CardModel>(cardProviderFunc_());
    }
    return *serviceCard_;
}

void Client::verifyResponse(const Response& response) const {
    auto responseHeader = response.header();
    auto responseData = responseHeader[http::kHeaderField_ResponseId] + response.body();
    auto responseSign = responseHeader[http::kHeaderField_ResponseSign];
    auto publicKey = this->getServiceCard().getPublicKey().getKey();
    if (!VirgilSigner().verify(str2bytes(responseData), VirgilBase64::decode(responseSign), publicKey)) {
        throw std::runtime_error("Client: The response verification has failed. Signature doesn't match.");
    }
}
