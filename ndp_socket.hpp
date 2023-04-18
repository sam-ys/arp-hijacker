#ifndef _comm_ndp_socket_hpp
#define _comm_ndp_socket_hpp

#include <cstddef>

namespace comm {

    //! @class ip6_addr
    /*! ip v6 address */
    struct ip6_addr {
        char ip6[32];
        char mac[32];
    };

    //! @class ndp socket
    /*!*/
    class ndp_socket {
    public:

        static ndp_socket create_broadcast(const char* interface);

        static ndp_socket create_spoofed_gateway(const char*     interface,
                                                 const ip6_addr& tgtAddr,
                                                 const char*     gatewayAddr);

        static ndp_socket create_spoofed_machine(const char*     interface,
                                                 const ip6_addr& tgtAddr,
                                                 const char*     machineAddr);

        ndp_socket(const char* const interface, const ip6_addr& srcAddr);
        ndp_socket(const char* const interface, const ip6_addr& srcAddr, const ip6_addr& tgtAddr);

        ~ndp_socket();

        void close();

        bool send_reply() const;

        bool send_request() const;

    private:

        // Header length
        static const ::size_t PACKETLEN = 14 /* Ethernet header length */+ 28 /* NDP header length */;

        int sfd_;
        char header_[PACKETLEN];

        // Helper
        inline bool send_impl(const int opcode) const;
     };
}

#endif
