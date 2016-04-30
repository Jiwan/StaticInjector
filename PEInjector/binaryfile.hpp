#pragma once

#include <fstream>
#include <string>
#include <vector>

namespace peinjector
{
	class BinaryFile
	{
	public:
		BinaryFile() = default;

		BinaryFile(const std::string& filePath, std::ios_base::openmode mode)
		{
			open(filePath, mode);
		}

		bool open(const std::string& filePath, std::ios_base::openmode mode)
		{
			stream_.open(filePath, mode | std::fstream::binary);

			if (!stream_.is_open()) {
				return false;
			}

			seek(0, std::ios_base::end);
			size_ = tell();
			seek(0);

			return true;
		}

		void seek(std::size_t off, std::ios_base::seekdir dir = std::ios_base::beg)
		{
			stream_.seekg(off, dir);
		}

		std::size_t tell()
		{
			return stream_.tellg();
		}

		template <typename T>
		void read(T& t)
		{
			if (tell() + sizeof(T) > size_) {
				throw std::runtime_error("File end reached.");
			}

			stream_.read(reinterpret_cast<char*>(&t), sizeof(T));
		}

		template <typename T>
		T read()
		{
			T result;

			read(result);

			return result;
		}

		std::vector<char> readBuffer(std::size_t size)
		{
			if (tell() + size > size_) {
				throw std::runtime_error("File end reached.");
			}

			std::vector<char> buffer;
			buffer.resize(size);

			stream_.read(buffer.data(), size);

			return buffer;
		}

	private:
		std::string filePath_;
		std::size_t size_;
		std::fstream stream_;
	};
}