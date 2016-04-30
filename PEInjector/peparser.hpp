#pragma once

#include <cstdint>

#include "binaryfile.hpp"

// See: http://www.csn.ul.ie/~caolan/pub/winresdump/winresdump/doc/pefile.html
// And: https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files

namespace peinjector
{

	constexpr const char* MagicDOSSignature = "MZ";

	struct DOSHeader
	{
		std::uint8_t  magic[2];
		std::uint16_t lastSize;
		std::uint16_t numberBlocks;
		std::uint16_t numberRelocations;
		std::uint16_t hdrSize;
		std::uint16_t minAlloc;
		std::uint16_t maxAlloc;
		std::uint16_t ss;
		std::uint16_t sp;
		std::uint16_t checksum;
		std::uint16_t ip;
		std::uint16_t cs;
		std::uint16_t relocPos;
		std::uint16_t numberOverlay;
		std::uint16_t reserved1[4];
		std::uint16_t oem_id;
		std::uint16_t oem_info;
		std::uint16_t reserved2[10];
		std::uint32_t pointerToCoffHeader;
	};
	
	constexpr const std::uint32_t MagicPESignature = 0x00004550;  // PE00
	constexpr const std::uint16_t x86Signature = 0x014c;

	struct COFFHeader
	{
		std::uint32_t magic;
		std::uint16_t machine;
		std::uint16_t numberSections;
		std::uint16_t timeDateStamp;
		std::uint32_t pointerToSymbolTable;
		std::uint32_t numberOfSymbols;
		std::uint16_t sizeOfOptionalHeader;
		std::uint16_t characteristics;
	};

	struct DataDirectory
	{
		std::uint32_t virtualAddress;
		std::uint32_t size;
	};

	constexpr const int MaxDirectoryEntryCount = 16;
	constexpr const int MaxSectionCount = 64;

	struct PEOptHeader
	{
		// Standard fields
		std::uint16_t signature;
		std::uint8_t  majorLinkerVersion;
		std::uint8_t  minorLinkerVersion;
		std::uint32_t sizeOfCode;
		std::uint32_t sizeOfInitializedData;
		std::uint32_t sizeOfUninitializedData;
		std::uint32_t addressOfEntryPoint;
		std::uint32_t baseOfCode;
		std::uint32_t baseOfData;
		// NT additional fields
		std::uint32_t imageBase;
		std::uint32_t sectionAlignment;
		std::uint32_t fileAlignment;
		std::uint16_t majorOSVersion;
		std::uint16_t minorOSVersion;
		std::uint16_t majorImageVersion;
		std::uint16_t minorImageVersion;
		std::uint16_t majorSubsystemVersion;
		std::uint16_t minorSubsystemVersion;
		std::uint32_t win32VersionValue;
		std::uint32_t sizeOfImage;
		std::uint32_t sizeOfHeaders;
		std::uint32_t checksum;
		std::uint16_t subsystem;
		std::uint16_t dLLCharacteristics;
		std::uint32_t sizeOfStackReserve;
		std::uint32_t sizeOfStackCommit;
		std::uint32_t sizeOfHeapReserve;
		std::uint32_t sizeOfHeapCommit;
		std::uint32_t loaderFlags;
		std::uint32_t numberOfRvaAndSizes;
		DataDirectory dataDirectory[MaxDirectoryEntryCount];
	};

	struct SectionHeader {
		char name[8];
		
		union {
			std::uint32_t   physicalAddress;
			std::uint32_t   virtualSize;
		} Misc;

		std::uint32_t   virtualAddress;
		std::uint32_t   sizeOfRawData;
		std::uint32_t   pointerToRawData;
		std::uint32_t   pointerToRelocations;
		std::uint32_t   pointerToLinenumbers;
		std::uint16_t   numberOfRelocations;
		std::uint16_t   numberOfLinenumbers;
		std::uint32_t   characteristics;
	};


	class PEParser
	{
	public:
		PEParser()
		{

		}

		void parse(const std::string& pePath)
		{
			BinaryFile f(pePath, std::fstream::in);

			std::cout << "Reading DOS header" << std::endl;
			f.read(dosHeader_);

			if (!checkDOSHeader()) {
				std::cout << "Invalid DOS header, are you sure '" << pePath << "' is a PE?" << std::endl;
				throw std::runtime_error("Invalid DOS header");
			}

			std::cout << "Reading DOS stub" << std::endl;
			dosStub_ = f.readBuffer(dosHeader_.pointerToCoffHeader - sizeof(DOSHeader));

			std::cout << "Reading Coff Header" << std::endl;
			f.read(coffHeader_);

			if (!checkPESignature()) {
				std::cout << "Invalid Coff header, are you sure '" << pePath << "' is a PE?" << std::endl;
				throw std::runtime_error("Invalid Coff header");
			}

			std::cout << "Reading PE Opt Header" << std::endl;
			f.read(peOptHeader_);

			std::cout << "Reading sections headers" << std::endl;
			std::cout << "Number of sections: " << coffHeader_.numberSections << std::endl;

			for (int i = 0; i < coffHeader_.numberSections; ++i) {
				sectionHeaders_.push_back(f.read<SectionHeader>());
			}
		}

	private:
		bool checkDOSHeader()
		{
			std::cout << "Checking DOS header" << std::endl;

			if (std::memcmp(MagicDOSSignature, dosHeader_.magic, sizeof(dosHeader_.magic)) != 0) {
				std::cout << "Invalid magic DOS number" << std::endl;

				return false;
			}

			return true;
		}

		bool checkPESignature()
		{
			std::cout << "Checking Coff header" << std::endl;

			if (coffHeader_.magic != MagicPESignature) {
				std::cout << "Invalid magic PE number" << std::endl;
			
				return false;
			}

			if (coffHeader_.machine != x86Signature) {
				std::cout << "Invalid machine signature" << std::endl;

				return false;
			}

			if (coffHeader_.sizeOfOptionalHeader < sizeof(PEOptHeader)) {
				std::cout << "Optional header too small" << std::endl;

				return false;
			}

			if (coffHeader_.numberSections > MaxSectionCount) {
				std::cout << "The number of sections should be under " << MaxSectionCount << std::endl;

				return false;
			}

			return true;
		}

	private:
		DOSHeader dosHeader_;
		std::vector<char> dosStub_;
		COFFHeader coffHeader_;
		PEOptHeader peOptHeader_;
		std::vector<SectionHeader> sectionHeaders_;
	};
}