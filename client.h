#pragma once

#include <cstdint>
#include <string>

struct dns_cli_t
{
	uint16_t port;
	uint32_t server;
	std::string domain;
};

dns_cli_t processInput(int argc, char* argv[]);