#pragma once

#include <fstream>
#include <string>

struct Persistence {
  explicit Persistence(std::string path)
    : path_(std::move(path))
  {}

  int save(const uint8_t* sealed_data, const size_t sealed_size) const {
    std::ofstream file(path_, std::ios::out | std::ios::binary);

    if (file.fail()) {
      return 1;
    }

    file.write((const char*) sealed_data, sealed_size);
    file.close();

    return 0;
  }

  int load(uint8_t* sealed_data, const size_t sealed_size) const {
    std::ifstream file(path_, std::ios::in | std::ios::binary);

    if (file.fail()) {
      return 1;
    }

    file.read((char*) sealed_data, sealed_size);
    file.close();

    return 0;
  }

  const size_t size() const {
    // check file size
    std::ifstream in(path_, std::ifstream::ate | std::ifstream::binary);
    return in.tellg();
  }

  const bool exists() const {
    // check if file exists
    std::ifstream f(path_.c_str());
    return f.good();
  }

  const std::string path() const {
    return path_;
  }

private:
  std::string path_;
};
