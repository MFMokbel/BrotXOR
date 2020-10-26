    #pragma once
    
    #include <iostream>
    #include <array>
    #include <string>
    #include <algorithm>
    #include <vector>
    #include <map>
    #include <iomanip>
    #include <cctype>
    // https://github.com/imfl/color-console
    #include "color.hpp"
    
    using kv_t = std::map<std::uint8_t, std::uint8_t>;
    
    void check_arg(int argc, char *argv[]);
    template<typename arr_t>
    void print_header(const std::string prt, const std::uint16_t i, arr_t const &msg);
    void save_data(kv_t &p_1, std::uint8_t k, std::uint8_t r);
    void print_data(kv_t &p_1);
    void delete_non_common(kv_t &p_1, kv_t &p_2);
    void version_info(void);
    
    namespace opt
    {
    	bool alpha  = false;
    	bool digit  = false;
    	bool other  = false;
    	bool reduce = false;
    }; // arg options
    
    // counter for recording all deleted non-common keys between p_1 and p_2
    std::size_t nb_non_common_p1 = 0;
    std::size_t nb_non_common_p2 = 0;
