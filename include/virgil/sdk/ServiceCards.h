#ifndef VIRGIL_SDK_SERVICE_CARDS_H
#define VIRGIL_SDK_SERVICE_CARDS_H

#include <virgil/sdk/model/Card.h>

namespace virgil {
namespace sdk {
    /**
     * @brief This class specify interface which provide Virgil Services Cards
     */
    class ServiceCards {
    public:
        /**
         * @brief Return Virgil Card of Virgil Keys Service
         *
         * @note This card is used for two clients: PublicKeyKlient and CardClient
         */
        virtual virgil::sdk::model::Card loadKeyServiceCard() const = 0;
        /**
         * @brief Return Virgil Card of Virgil PrivateKeys Service
         */
        virtual virgil::sdk::model::Card loadPrivateKeyServiceCard() const = 0;
        /**
         * @brief Return Virgil Card of Virgil Identity Service
         */
        virtual virgil::sdk::model::Card loadIdentityServiceCard() const = 0;
        /**
         * @brief Empty destructor
         */
        // clang-format off
    virtual ~ServiceCards() noexcept {}
        // clang-format on
    };
} // sdk
} // virgil

#endif /* VIRGIL_SDK_SERVICE_CARDS_H */
