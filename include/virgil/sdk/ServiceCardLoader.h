#ifndef VIRGIL_SDK_SERVICE_CARD_LOADER_H
#define VIRGIL_SDK_SERVICE_CARD_LOADER_H

#include <virgil/sdk/models/Card.h>

namespace virgil {
namespace sdk {
    /**
     * @brief This class specify interface which provide Virgil Services Cards
     */
    class ServiceCardLoader {
    public:
        /**
         * @brief Return Virgil Card of Virgil Keys Service
         *
         * @note This card is used for two clients: PublicKeyKlient and CardClient
         */
        virtual virgil::sdk::models::Card loadKeyServiceCard() const = 0;
        /**
         * @brief Return Virgil Card of Virgil PrivateKeys Service
         */
        virtual virgil::sdk::models::Card loadPrivateKeyServiceCard() const = 0;
        /**
         * @brief Return Virgil Card of Virgil Identity Service
         */
        virtual virgil::sdk::models::Card loadIdentityServiceCard() const = 0;
        /**
         * @brief Empty destructor
         */
        // clang-format off
    virtual ~ServiceCardLoader() noexcept {}
        // clang-format on
    };
} // sdk
} // virgil

#endif /* VIRGIL_SDK_SERVICE_CARD_LOADER_H */
