#include <virgil/IPMessaging/ChatMember.h>

namespace vipm = virgil::IPMessaging;

vipm::ChatMember::ChatMember(const virgil::sdk::models::CardModel& card,
                             const virgil::crypto::VirgilByteArray& privateKey)
        : card_(card), privateKey_(privateKey) {
}

virgil::sdk::models::CardModel vipm::ChatMember::getCard() const {
    return card_;
}

std::string vipm::ChatMember::getIdentity() const {
    return card_.getCardIdentity().getValue();
}

virgil::crypto::VirgilByteArray vipm::ChatMember::getCardId() const {
    return virgil::crypto::str2bytes(card_.getId());
}

virgil::crypto::VirgilByteArray vipm::ChatMember::getPublicKey() const {
    return card_.getPublicKey().getKey();
}

virgil::crypto::VirgilByteArray vipm::ChatMember::getPrivateKey() const {
    return privateKey_;
}
