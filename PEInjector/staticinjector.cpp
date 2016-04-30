#include <iostream>

#include "peparser.hpp"

using namespace peinjector;

int main(int argc, char* argv[])
{

	if (argc > 1) {
		PEParser parser;
		parser.parse(argv[1]);
	}
	else {
		std::cout << "Nothing to parse" << std::endl;
	}

	system("PAUSE");

    return 0;
}

