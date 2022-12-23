#pragma once

#include <cinttypes>

#include <vector>
#include <string>
#include <memory>

// DNS defines

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

#define DNS_MSG_MAX_SIZE 512

namespace dns 
{
    // For serialization 

    struct buffer_t
    {
        size_t len;
        std::unique_ptr<uint8_t[]> data;
    };

    // Allocate buffer

    buffer_t allocate(size_t len);

    // DNS header structure

    struct dns_header_t
    {
        unsigned short id; // identification number

        unsigned char rd : 1; // recursion desired
        unsigned char tc : 1; // truncated message
        unsigned char aa : 1; // authoritive answer
        unsigned char opcode : 4; // purpose of message
        unsigned char qr : 1; // query/response flag

        unsigned char rcode : 4; // response code
        unsigned char cd : 1; // checking disabled
        unsigned char ad : 1; // authenticated data
        unsigned char z : 1; // its z! reserved
        unsigned char ra : 1; // recursion available

        unsigned short q_count; // number of question entries
        unsigned short ans_count; // number of answer entries
        unsigned short auth_count; // number of authority entries
        unsigned short add_count; // number of resource entries
    };

#pragma pack(push, 1)
    struct r_data_t
    {
        unsigned short type;
        unsigned short _class;
        unsigned int ttl;
        unsigned short data_len;
    };
#pragma pack(pop)

    using qclass_t = unsigned short;
    using qtype_t = unsigned short;

    // Simplified version of message
    // one question 
    // only answers allowed

    class Message 
    {
        uint64_t _id;
        std::string _question;
        std::vector<uint64_t> _ips;

    public:
        Message() = default;
        Message(const Message& other) = delete;
        Message(Message&& move) = default;
        ~Message() = default;

        void setId(uint64_t id);
        void setQuestion(const std::string& question);
        void addIp(uint64_t ip);

        uint64_t getId() const;
        std::string getQuestion() const;
        std::vector<uint64_t> getIps() const;
    };

    bool isQuestionsEqual(const std::string& q1, const std::string& q2);

    // Serialization type

    buffer_t serializeRequest(const Message& msg);
    buffer_t serializeResponse(const Message& msg);
    Message deserializeRequest(const buffer_t& data);
    Message deserializeResponse(const buffer_t& data);

    // UDP send and recieve request/response
    
    buffer_t sendRequest(uint64_t ip, uint16_t port, const buffer_t& data);


    namespace details
    {
        buffer_t buildQName(const std::string& question);
    }
}
