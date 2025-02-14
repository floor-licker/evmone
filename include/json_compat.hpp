#pragma once
#include <glaze/glaze.hpp>
#include <optional>
#include <string_view>
#include <vector>

// This is a compatibility layer - we should check if we can remove nlohmann::json
// dependencies and update it to use only glaze

// Compatibility layer to make transition smoother
namespace json {
    using value = glz::json_t;  // Replace nlohmann::json
    
    template<typename T>
    T get(const value& j) {
        T val;
        glz::read<T>(j, val);
        return val;
    }
    
    template<typename T>
    value parse(T&& t) {
        return glz::read_json(std::forward<T>(t));
    }
    
    // Add common nlohmann functions
    template<typename T>
    std::optional<T> get_optional(const value& j, std::string_view key) {
        if (auto it = j.find(key); it != j.end()) {
            T val;
            glz::read(*it, val);
            return val;
        }
        return std::nullopt;
    }
    
    template<typename T>
    T value_or(const value& j, std::string_view key, T default_value) {
        return get_optional<T>(j, key).value_or(default_value);
    }
    
    inline bool contains(const value& j, std::string_view key) {
        return j.find(key) != j.end();
    }
    
    template<typename T>
    void write(value& j, std::string_view key, const T& val) {
        glz::write(j[std::string(key)], val);
    }
    
    // Add other commonly used nlohmann functions as needed

    template<typename T>
    T at(const value& j, std::string_view key) {
        auto it = j.find(key);
        if (it == j.end()) {
            throw std::out_of_range("key not found: " + std::string(key));
        }
        T val;
        glz::read(*it, val);
        return val;
    }

    template<typename T>
    std::vector<T> get_array(const value& j, std::string_view key) {
        std::vector<T> result;
        if (auto it = j.find(key); it != j.end()) {
            glz::read(*it, result);
        }
        return result;
    }

    inline value object() {
        return glz::json_t::object();
    }

    inline value array() {
        return glz::json_t::array();
    }
} 