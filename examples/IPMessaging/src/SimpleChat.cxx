#include <iostream>
#include <vector>
#include <functional>
#include <fstream>

#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/VirgilSigner.h>
#include <virgil/crypto/VirgilCipher.h>
#include <virgil/crypto/foundation/VirgilBase64.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>

#include "SimpleChat.h"
#include "Constants.h"
#include "models/EncryptedMessageModel.h"

namespace vcrypto = virgil::crypto;
namespace vsdk = virgil::sdk;
namespace vipm = virgil::IPMessaging;

vipm::SimpleChat::~SimpleChat() {
    std::ofstream logging("log-file.txt");
    logging << logFile_;
}

void vipm::SimpleChat::launch() {
    std::cout << std::endl;
    std::cout << "Enter Email Address" << std::endl;

    std::string emailAddress;
    std::cin >> emailAddress;

    currentMember_ = this->autorize(emailAddress);
    client_ = vipm::Client(currentMember_.getIdentity());

    std::cout << "Welcome to DARKSIDE chat. Feel free to post here your DARK thoughts." << std::endl;
    startMessaging();
}

void vipm::SimpleChat::startMessaging() {
    channel_ = this->client_.joinChannel("DARKSIDE");

    using std::placeholders::_1;
    using std::placeholders::_2;
    channel_.messageRecived.push_back(std::bind(&vipm::SimpleChat::onMessageRecived, this, _1, _2));

    bool keepWorking = true;
    while (keepWorking) {
        std::cout << currentMember_.getIdentity() << "; ";
        std::cout << "Enter message:" << std::endl;
        std::string message;
        std::cin >> std::ws;
        std::getline(std::cin, message);
        this->onMessageSend(message);
        channel_.watch();
    }
}

void vipm::SimpleChat::onMessageSend(const std::string& message) {
    MapCardIdPublicKey channelRecipients = this->getChannelRecipients();
    vcrypto::VirgilCipher cipher;
    for (const auto& channelRecipient : channelRecipients) {
        auto recipientCardId = channelRecipient.first;
        auto recipientPublicKey = channelRecipient.second;
        cipher.addKeyRecipient(recipientCardId, recipientPublicKey);
    }

    vcrypto::VirgilByteArray encryptedMessage = cipher.encrypt(vcrypto::str2bytes(message), true);

    vcrypto::VirgilSigner signer;
    vcrypto::VirgilByteArray signature = signer.sign(encryptedMessage, currentMember_.getPrivateKey());

    vipm::models::EncryptedMessageModel encryptedModel(encryptedMessage, signature);
    std::string encryptedModelJson = vipm::models::toJson(encryptedModel);

    channel_.sendMessage(encryptedModelJson);
}

void vipm::SimpleChat::onMessageRecived(const std::string& sender, const std::string& message) {
    vipm::models::EncryptedMessageModel encryptedModel = vipm::models::fromJson(message);
    if (encryptedModel.isEmpty()) {
        return;
    }

    bool includeUnconfirmed = true;
    vsdk::dto::Identity senderIdentity(sender, "email");
    auto foundCards = servicesHub_.card().search(senderIdentity, includeUnconfirmed);
    if (foundCards.empty()) {
        return;
    }

    auto senderCard = foundCards.at(0);

    std::cout << sender << " -> ";
    vcrypto::VirgilSigner signer;
    bool isValid =
        signer.verify(encryptedModel.getMessage(), encryptedModel.getSignature(), senderCard.getPublicKey().getKey());
    if (!isValid) {
        std::cout << "The message signature is not valid." << std::endl;
        logFile_ += sender + " .The message signature is not valid.";
        std::cout << std::endl;
        return;
    }

    try {
        vcrypto::VirgilCipher cipher;
        vcrypto::VirgilByteArray decryptedMessage =
            cipher.decryptWithKey(encryptedModel.getMessage(), currentMember_.getCardId(),
                                  currentMember_.getPrivateKey(), vcrypto::VirgilByteArray());

        std::cout << vcrypto::bytes2str(decryptedMessage) << std::endl;
        std::cout << std::endl;

    } catch (std::exception& exception) {
        std::cout << std::string("Can't decrypt message.") << std::endl;
        logFile_ += std::string("Can't decrypt message. Error: ") + exception.what() + "\n";
        std::cout << std::endl;
    }
}

vipm::ChatMember vipm::SimpleChat::autorize(const std::string& emailAddress) {
    vsdk::dto::Identity identity(emailAddress, "email");

    bool includeUnconfirmed = true;
    std::vector<vsdk::models::CardModel> foundCards = servicesHub_.card().search(identity, includeUnconfirmed);
    if (foundCards.empty()) {
        return registerUser(emailAddress);
    }

    std::string actionId = servicesHub_.identity().verify(identity);
    std::cout << "The email with confirmation code has been sent to your"
                 " email address. Please check it!"
              << std::endl;
    std::cout << "Enter code:" << std::endl;
    std::string confirmationCode;
    std::cin >> confirmationCode;

    vsdk::dto::ValidatedIdentity validatedIdentity = servicesHub_.identity().confirm(actionId, confirmationCode);

    vsdk::models::CardModel card = foundCards.at(0);
    vsdk::models::PrivateKeyModel privateKeyModel = servicesHub_.privateKey().get(card.getId(), validatedIdentity);

    return vipm::ChatMember(card, privateKeyModel.getKey());
}

vipm::ChatMember vipm::SimpleChat::registerUser(const std::string& email) {
    // generate a new public/private key pair.
    vcrypto::VirgilKeyPair newKeyPair;

    // The app is registering a Virgil Card which includes a
    // public key and an email address identifier. The card will
    // be used for the public key identification and searching
    // for it in the Public Keys Service.
    vsdk::dto::Identity identity(email, "email");
    vsdk::Credentials credentials(newKeyPair.privateKey());
    vsdk::models::CardModel card = servicesHub_.card().create(identity, newKeyPair.publicKey(), credentials);

    // Private key can be added to Virgil Security storage if you want to
    // easily synchronise yout private key between devices.
    servicesHub_.privateKey().add(card.getId(), credentials);

    return ChatMember(card, newKeyPair.privateKey());
}

MapCardIdPublicKey vipm::SimpleChat::getChannelRecipients() {
    auto channelMembers = channel_.getMembers();
    std::vector<vsdk::models::CardModel> recipientsCards;
    for (const auto& channelMember : channelMembers) {
        vsdk::dto::Identity identity(channelMember, "email");
        bool includeUnconfirmed = true;
        auto foundCards = servicesHub_.card().search(identity, includeUnconfirmed);
        recipientsCards.insert(std::end(recipientsCards), std::begin(foundCards), std::end(foundCards));
    }

    MapCardIdPublicKey recipients;
    for (const auto& recipientsCard : recipientsCards) {
        auto cardId = vcrypto::str2bytes(recipientsCard.getId());
        recipients[cardId] = recipientsCard.getPublicKey().getKey();
    }

    return recipients;
}
