#include "server.h"
#include "dns.cpp"

#include <netinet/in.h>
#include <cstring>

#include <iostream>

int main(int argc, char* argv[]) {
  uint16_t port = processInput(argc, argv);

  int socketfd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in address;
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);

  const int r = bind(socketfd, (struct sockaddr*)&address, sizeof(address));

  if (r == -1) {
    std::cerr << "Socket already taken" << std::endl;
    std::exit(1);
  }

  listen(socketfd, 5);

  while (true) {
    struct sockaddr_in cliaddr;

    socklen_t slen = sizeof(cliaddr);

    memset(&cliaddr, 0, sizeof(cliaddr));

    uint8_t request_buffer[DNS_MSG_MAX_SIZE];
    ssize_t request_len = recvfrom(socketfd, request_buffer, DNS_MSG_MAX_SIZE,
                                   0, (struct sockaddr*)&cliaddr, &slen);

    dns::buffer_t request_data = dns::allocate(request_len);

    memcpy(request_data.data.get(), request_buffer, request_len);

    dns::Message request = dns::deserializeRequest(request_data);
    dns::Message response;

    response.setId(request.getId());
    response.setQuestion(request.getQuestion());

    uint64_t ip_value = request.getQuestion().size() + 1;

    response.addIp(ip_value);

    dns::buffer_t response_data = dns::serializeResponse(response);

    sendto(socketfd, response_data.data.get(), response_data.len, 0,
           (struct sockaddr*)&cliaddr, (socklen_t)sizeof(cliaddr));
  }

  return 0;
}

uint16_t processInput(int argc, char* argv[]) {
  if (argc >= 3) {
    std::cerr << "Usage:\n" << argv[0] << " [port]" << std::endl;
    std::exit(1);
  }

  uint16_t port = 53;

  if (argc >= 2) {
    size_t i = 0;
    int value = std::stoi(std::string(argv[1]).substr(0, 6), &i);

    if (argv[1][i] != '\0' || value <= 0 || value >= 65536) {
      std::cerr << "Invalid port:\n" << argv[1] << std::endl;
      std::exit(-1);
    }

    port = value;
  }

  return port;
}