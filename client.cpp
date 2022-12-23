#include "client.h"
#include "dns.cpp"

#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
  dns_cli_t input = processInput(argc, argv);

  srand(time(0));

  dns::Message request;

  request.setId(((uint64_t)(rand() % 0xFF) << 8) + (uint64_t)(rand() % 0xFF));
  request.setQuestion(input.domain);

  dns::buffer_t request_data = dns::serializeRequest(request);
  dns::buffer_t response_data =
      dns::sendRequest(input.server, input.port, request_data);

  dns::Message response = dns::deserializeResponse(response_data);

  if (request.getId() != response.getId() ||
      !dns::isQuestionsEqual(request.getQuestion(), response.getQuestion())) {
    std::cout << request.getId() << " " << response.getId() << " "
              << request.getQuestion() << " " << response.getQuestion()
              << std::endl;
    std::cerr << "Wrong DNS id or question recieved!" << std::endl;
    std::exit(1);
  }

  if (response.getIps().size() == 0) {
    std::cout << "Could not resolve ip of \"" << request.getQuestion() << "\""
              << std::endl;
    std::exit(1);
  }

  std::cout << "DNS resolve of \"" << request.getQuestion()
            << "\" is:" << std::endl;

  for (const uint64_t& answer : response.getIps()) {
    std::cout << "- " << std::to_string((answer >> (8 * 3)) & 0xFF) << "."
              << std::to_string((answer >> (8 * 2)) & 0xFF) << "."
              << std::to_string((answer >> (8 * 1)) & 0xFF) << "."
              << std::to_string((answer >> (8 * 0)) & 0xFF) << std::endl;
  }

  return 0;
}

dns_cli_t processInput(int argc, char* argv[]) {
  if (argc == 1 || argc >= 5) {
    std::cerr << "Usage:\n"
              << argv[0] << " dns_name [server] [port]" << std::endl;
    std::exit(1);
  }

  uint32_t server_address = 0;
  std::string server("127.0.0.1");

  if (argc >= 3) server = std::string(argv[2]);

  char expected[] = {'.', '.', '.', '\0'};
  size_t index = 0, old = 0;

  for (int i = 0; i != 4; i++) {
    const int value = std::stoi(server.substr(index, 15 - index), &old);

    if (server[index + old] != expected[i]) {
      std::cerr << "Invalid ip:\n" << server << std::endl;
      std::exit(1);
    }

    if (value < 0 || value >= 256) {
      std::cerr << "Invalid ip:\n" << server << std::endl;
      std::exit(1);
    }

    server_address += value * (1 << (8 * (3 - i)));
    index += old + 1;
  }

  uint16_t port = 53;

  if (argc >= 4) {
    size_t i = 0;
    int value = std::stoi(std::string(argv[3]).substr(0, 6), &i);

    if (argv[3][i] != '\0' || value <= 0 || value >= 65536) {
      std::cerr << "Invalid port:\n" << argv[3] << std::endl;
      std::exit(1);
    }

    port = value;
  }

  dns_cli_t data;

  data.domain = argv[1];
  data.server = server_address;
  data.port = port;

  return data;
}
