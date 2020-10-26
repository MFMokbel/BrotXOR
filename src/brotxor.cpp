    /*
    Author
    Mohamad Mokbel
    
    Tool: BrotXOR
    Date: August 22, 2020
    
    Version 1.0
    
    BrotXOR is a tool that helps in demonstrating a possible reduction
    based attack against XOR encrypted data with a key.length() > 1. This
    is useful when not enough repeating blocks exist!
    
    Args accepted (one at a time):
    
    	-a  (prints only the keys with alpha values)
    	-d  (prints only the keys with digit values)
    	-o  (prints only the keys with neither digit nor alpha values)
    	-r  (prints original k:v with same keys only)
    
    note: if no argument is passed, it prints original k:v
    */
    
    #include "brotxor.h"
    
    int main(int argc, char *argv[])
    {
    	check_arg(argc, argv);
    
    	std::cout << std::endl
    		<< dye::blue("[") << " Find Matching Keys (XOR) " << dye::blue("]")
    		<< std::endl;
    
    	// possible characters of plain text
    	constexpr std::array<std::uint8_t, 68> alphabet =
    	{
    		'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x',
    		'y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V',
    		'W','X','Y','Z','0','1','2','3','4','5','6','7','8','9','+','_','&','!','{','}'
    	};
    	// correct key(md5-hash value): 87b2e8649b4eb5daa3ce24494517214e
    	// reduced from 32 to 16 bytes
    	constexpr std::array<std::uint8_t, 16> key_exp =
    	{
      /*  a     b     c     d     e     f     0     1     2     3     4     5     6     7     8     9  */
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39
    	};
    	/*
    	length of encrypted/decrypted data: 59 (already known)
    	decrypted: AMCAG{Strawberry_is_THE_best_thing_ever_in_this_world_end!}
    	*/
    	constexpr std::array<std::uint8_t, 59> msg_e =
    	{
    		// p_1[0-26]
    		0x79, 0x7a, 0x21, 0x73, 0x22, 0x43, 0x65, 0x40, 0x4b, 0x03, 0x43, 0x07, 0x07, 0x47, 0x16, 0x18, 
    		0x3e, 0x5a, 0x10, 0x3a, 0x66, 0x7c, 0x71, 0x66, 0x56, 0x50, 0x42, 
    		// p_3[27-31]
    		0x43, 0x6d, 0x45, 0x5c, 0x0c, 
    		// p_2[32-58]
    		0x56, 0x50, 0x3d, 0x57, 0x13, 0x5d, 0x44, 0x6b, 0x50, 0x0c, 0x6b, 0x11, 0x0a, 0x5c, 0x17, 0x3e,
    		0x16, 0x5c, 0x11, 0x09, 0x56, 0x6b, 0x51, 0x57, 0x50, 0x14, 0x4c
    	};
    
    	kv_t p_1 = {};
    	kv_t p_2 = {};
    	kv_t p_3 = {};
    	std::vector<std::uint8_t> key_exp_r = {};
    
    	std::cout << std::endl;
    
    	for (std::uint16_t i = 0; i < 27; ++i)
    	{
    		for (std::uint8_t r = 0; r < alphabet.size(); ++r)
    		{
    			for (std::uint8_t k = 0; k < key_exp.size(); ++k)
    			{
    				if (((alphabet.at(r) ^ key_exp.at(k)) == (msg_e.at(i))))
    				{
    					key_exp_r.push_back(key_exp.at(k));
    					save_data(p_1, key_exp.at(k), alphabet.at(r));
    				}
    			}
    		}
    
    		for (std::uint8_t r = 0; r < alphabet.size(); ++r)
    		{
    			for (std::uint8_t kr = 0; kr < key_exp_r.size(); ++kr)
    			{
    				if (((alphabet.at(r) ^ key_exp_r.at(kr)) == (msg_e.at(i + 32))))
    				{
    					save_data(p_2, key_exp_r.at(kr), alphabet.at(r));
    				}
    			}
    		}
    
    		if (opt::reduce)
    		{
    			// two rounds
    			delete_non_common(p_1, p_2);
    			delete_non_common(p_1, p_2);
    		}
    
    		print_header("p_1", i, msg_e);
    		print_data(p_1);
    
    		std::cout << std::endl;
    
    		print_header("p_2", i + 32, msg_e);
    		print_data(p_2);
    
    		std::cout << std::endl << std::endl;
    
    		key_exp_r.clear();
    		p_1.clear();
    		p_2.clear();
    	}
    
    	// non repeating key part (last 5 bytes of the key)
    	std::cout << dye::aqua("---------") << std::endl << std::endl;
    
    	for (std::uint16_t i = 27; i < 32; ++i)
    	{
    		for (std::uint8_t r = 0; r < alphabet.size(); ++r)
    		{
    			for (std::uint8_t k = 0; k < key_exp.size(); ++k)
    			{
    				if (((alphabet.at(r) ^ key_exp.at(k)) == (msg_e.at(i))))
    				{
    					save_data(p_3, key_exp.at(k), alphabet.at(r));
    				}
    			}
    		}
    		print_header("p_3", i, msg_e);
    		print_data(p_3);
    
    		std::cout << std::endl;
    
    		p_3.clear();
    	}
    
    	if (opt::reduce)
    	{
    		std::cout << std::endl << dye::aqua("---------") << std::endl << std::endl
    			<< "+ Number of deleted non-common keys between " << std::dec
    			<< dye::purple("p_1: ") << nb_non_common_p1 << " and "
    			<< dye::purple("p_2: ") << nb_non_common_p2 << std::endl;
    	}
    	return 0;
    }
    
    template<typename arr_t>
    void
    print_header(const std::string prt, const std::uint16_t i, arr_t const &msg)
    {
    	std::cout << prt
    		<< dye::green("[")
    		<< std::setfill('0') << std::setw(2) << std::right << std::dec
    		<< i
    		<< dye::green("]") << dye::green("(")
    		<< "0x" << std::setfill('0') << std::setw(2) << std::right << std::hex
    		<< static_cast<int>(msg.at(i))
    		<< dye::green(")") << " = ";
    }
    
    void
    delete_non_common(kv_t &p_1, kv_t &p_2)
    {
    	if (p_1.size() > p_2.size())
    	{
    		for (auto i = p_1.begin(); i != p_1.end();)
    		{
    			if (auto it = p_2.find(i->first) == p_2.end())
    			{
    				p_1.erase(i->first);
    				nb_non_common_p1++;
    			}
    			++i;
    		}
    	}
    
    	if (p_2.size() > p_1.size())
    	{
    		for (auto i = p_2.begin(); i != p_2.end();)
    		{
    			if (auto it = p_1.find(i->first) == p_1.end())
    			{
    				p_2.erase(i->first);
    				nb_non_common_p2++;
    			}
    			++i;
    		}
    	}
    }
    
    void
    save_data(kv_t &p_1, std::uint8_t k, std::uint8_t r)
    {
    	if (opt::alpha)
    	{
    		if (std::isalpha(static_cast<unsigned char>(r)))
    		{
    			p_1.insert({ k, r });
    		}
    		return;
    	}
    
    	if (opt::digit)
    	{
    		if (std::isdigit(static_cast<unsigned char>(r)))
    		{
    			p_1.insert({ k, r });
    		}
    		return;
    	}
    
    	if (opt::other)
    	{
    		if (!std::isalpha(static_cast<unsigned char>(r)) && !std::isdigit(static_cast<unsigned char>(r)))
    		{
    			p_1.insert({ k, r });
    		}
    		return;
    	}
    
    	p_1.insert({ k, r });
    }
    
    void
    print_data(kv_t &p_1)
    {
    	for (const auto&[k, v] : p_1)
    	{
    		std::cout << k << ":" << v << " ";
    	}
    }
    
    void
    check_arg(int argc, char *argv[])
    {
    	if (argc > 1)
    	{
    		if (!_stricmp(argv[1], "-a"))
    			opt::alpha = true;
    		else if (!_stricmp(argv[1], "-d"))
    			opt::digit = true;
    		else if (!_stricmp(argv[1], "-o"))
    			opt::other = true;
    		else if (!_stricmp(argv[1], "-r"))
    			opt::reduce = true;
    		else if (!_stricmp(argv[1], "-v"))
    		{
    			version_info();
    			exit(0);
    		}
    		else
    		{
    			std::cout << std::endl << "+ Wrong argument!" << std::endl;
    			exit(0);
    		}
    	}
    }
    
    void
    version_info(void)
    {
    	std::cout << std::endl << "BrotXOR v1.0" << std::endl << std::endl
    
    		<< "A tool that helps in demonstrating a possible reduction based " << std::endl
    		<< "attack against XOR encrypted data with a key.length() > 1, and" << std::endl
    		<< "a max. of 2 repeating blocks." << std::endl << std::endl
    		<< "Release Date: August 22, 2020" << std::endl 
    		<< "Mohamad Mokbel" << std::endl << std::endl;
    }
