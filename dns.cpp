#include "dns.h"

#include <netinet/in.h>
#include <cstring>
#include <iostream>

namespace dns {
void Message::setId(uint64_t id) { _id = id; }

void Message::setQuestion(const std::string& question) { _question = question; }

void Message::addIp(uint64_t ip) { _ips.push_back(ip); }

uint64_t Message::getId() const { return _id; }

std::string Message::getQuestion() const { return _question; }

std::vector<uint64_t> Message::getIps() const { return _ips; }
}  // namespace dns

namespace dns {
buffer_t allocate(size_t len) {
  buffer_t buffer;

  buffer.len = len;
  buffer.data = std::make_unique<uint8_t[]>(len);

  return buffer;
}

bool isQuestionsEqual(const std::string& q1, const std::string& q2) {
  return q1 == q2 || (q1.size() > q2.size() ? q1 == q2 + "." : q2 == q1 + ".");
}

buffer_t serializeRequest(const Message& msg) {
  buffer_t buffer =
      allocate(sizeof(dns_header_t) + (msg.getQuestion().size() + 2) +
               sizeof(qclass_t) + sizeof(qtype_t));

  dns_header_t header;

  memset(&header, 0, sizeof(dns_header_t));

  header.id = htons(msg.getId());
  header.rd = 1;
  header.q_count = htons(1);
  header.qr = 0;

  buffer_t qname = details::buildQName(msg.getQuestion());

  qtype_t qtype = htons(T_A);
  qclass_t qclass = htons(1);

  uint8_t* it = buffer.data.get();

  memcpy(it, &header, sizeof(header));

  it += sizeof(header);

  memcpy(it, qname.data.get(), qname.len);

  it += qname.len;

  memcpy(it, &qtype, sizeof(qtype));

  it += sizeof(qtype);

  memcpy(it, &qclass, sizeof(qclass));

  return buffer;
}

buffer_t serializeResponse(const Message& msg) {
  std::string host = msg.getQuestion();

  dns_header_t header;
  memset(&header, 0, sizeof(header));

  header.id = htons(msg.getId());
  header.rd = 1;
  header.qr = 1;
  header.ans_count = htons(1);
  header.q_count = htons(1);

  qtype_t qtype = htons(T_A);
  qclass_t qclass = htons(1);

  buffer_t qname = details::buildQName(host);

  buffer_t packet =
      allocate(sizeof(header) + (host.size() + 2) + sizeof(qtype_t) +
               sizeof(qclass_t) + 4 + 2 + 2 + 4 + 2 + 4);

  memset(packet.data.get(), 0, packet.len);
  uint8_t* p = packet.data.get();

  memcpy(p, &header, sizeof(header));
  p += sizeof(header);

  const size_t t = host.size() == 0 ? 1 : host.size() + 2;

  memcpy(p, qname.data.get(), t);
  p += t;

  memcpy(p, &qtype, sizeof(qtype_t));
  p += sizeof(qtype_t);

  memcpy(p, &qclass, sizeof(qclass_t));

  p += sizeof(qclass_t);

  p[0] = 0xc0;
  p[1] = 0x0c;

  p += 2;

  // Type a
  p[0] = 0x0;
  p[1] = 0x1;

  p += 2;

  p[0] = 0x0;
  p[1] = 0x1;

  p += 2;

  p[0] = 0x0;
  p[1] = 0x0;
  p[2] = 0x0;
  p[3] = 0x0;

  p += 4;

  p[0] = 0x0;
  p[1] = 0x4;

  p += 2;

  const size_t tt = 1 + host.size();

  p[0] = (tt >> (8 * 3)) & 0xFF;
  p[1] = (tt >> (8 * 2)) & 0xFF;
  p[2] = (tt >> (8 * 1)) & 0xFF;
  p[3] = (tt >> (8 * 0)) & 0xFF;

  return packet;
}

Message deserializeRequest(const buffer_t& data) {
  Message msg;

  dns_header_t header;

  memcpy(&header, data.data.get(), sizeof(dns_header_t));

  header.id = ntohs(header.id);
  header.q_count = ntohs(header.q_count);
  header.ans_count = ntohs(header.ans_count);
  header.auth_count = ntohs(header.auth_count);
  header.add_count = ntohs(header.add_count);

  msg.setId(header.id);

  if (header.ans_count != 0 || header.q_count != 1 || header.rcode != 0 ||
      header.z != 0) {
    std::cerr << "Failed to get response" << std::endl;
    std::exit(1);
  }

  uint8_t* start_of_qs = data.data.get() + sizeof(dns_header_t);

  for (short i = 0; i != header.q_count; i++) {
    std::string q;

    while (*start_of_qs != 0) {
      std::string s(*start_of_qs + 1, '.');

      for (int j = 0; j != *start_of_qs; j++) {
        s[j] = (char)start_of_qs[j + 1];
      }

      start_of_qs += *start_of_qs + 1;
      q += s;
    }

    msg.setQuestion(q.substr(0, q.size() - 1));

    start_of_qs++;
    start_of_qs += sizeof(qclass_t) + sizeof(qtype_t);
  }

  return msg;
}

Message deserializeResponse(const buffer_t& data) {
  Message msg;

  dns_header_t header;

  memcpy(&header, data.data.get(), sizeof(dns_header_t));

  header.id = ntohs(header.id);
  header.q_count = ntohs(header.q_count);
  header.ans_count = ntohs(header.ans_count);
  header.auth_count = ntohs(header.auth_count);
  header.add_count = ntohs(header.add_count);

  msg.setId(header.id);

  if (header.qr != 1 || header.rcode != 0 || header.z != 0) {
    std::cerr << "Failed to get response" << std::endl;
    std::exit(-1);
  }

  uint8_t* start_of_qs = data.data.get() + sizeof(dns_header_t);

  for (short i = 0; i != header.q_count; i++) {
    std::string q;

    while (*start_of_qs != 0) {
      std::string s(*start_of_qs + 1, '.');

      for (int j = 0; j != *start_of_qs; j++) {
        s[j] = (char)start_of_qs[j + 1];
      }

      start_of_qs += *start_of_qs + 1;
      q += s;
    }

    q = q.substr(0, q.size() - 1);

    msg.setQuestion(q);

    start_of_qs++;
    start_of_qs += sizeof(qclass_t) + sizeof(qtype_t);
  }

  uint8_t* records = start_of_qs;

  for (short i = 0; i != header.ans_count; i++) {
    r_data_t record = {};

    while (*records != 0) records++;

    record.type = ntohs(*((uint16_t*)records));
    records += sizeof(uint16_t);
    record._class = ntohs(*(uint16_t*)records);
    records += sizeof(uint16_t);
    record.ttl = ntohl(*(uint32_t*)records);
    records += sizeof(uint32_t);
    record.data_len = ntohs(*(uint16_t*)records);
    records += sizeof(uint16_t);

    if (record.type == 1 && record.data_len == 4) {
      const uint64_t ip =
          ((uint64_t)records[0] << 8 * 3) + ((uint64_t)records[1] << 8 * 2) +
          ((uint64_t)records[2] << 8 * 1) + ((uint64_t)records[3] << 8 * 0);

      msg.addIp(ip);
    }
  }

  return msg;
}

namespace details {
buffer_t buildQName(const std::string& question) {
  buffer_t buffer = allocate(question.size() + 2);

  memcpy(buffer.data.get() + 1, question.c_str(), question.size());

  uint8_t count = 0;
  uint8_t* prev = (uint8_t*)buffer.data.get();

  for (size_t i = 0; i != question.size(); i++) {
    if (question[i] == '.') {
      *prev = count;
      prev = (uint8_t*)buffer.data.get() + i + 1;
      count = 0;
    } else {
      count++;
    }
  }

  *prev = count;
  buffer.data.get()[question.size() + 1] = '\0';

  return buffer;
}
}  // namespace details

buffer_t sendRequest(uint64_t ip, uint16_t port, const buffer_t& data) {
  struct timeval t;
  t.tv_sec = 5;
  t.tv_usec = 0;

  int socketfd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in address;
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(ip);
  address.sin_port = htons(port);

  if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t)) == -1)
    std::exit(1);

  sendto(socketfd, data.data.get(), data.len, 0, (struct sockaddr*)&address,
         (socklen_t)sizeof(address));

  socklen_t length = 0;
  uint8_t response[DNS_MSG_MAX_SIZE];

  int r = recvfrom(socketfd, response, DNS_MSG_MAX_SIZE, 0,
                   (struct sockaddr*)&address, &length);

  if (r == -1) {
    std::cerr << "Timeout" << std::endl;
    std::exit(1);
  }

  buffer_t response_data = allocate(r);

  memcpy(response_data.data.get(), response, r);

  return response_data;
}
}  // namespace dns
