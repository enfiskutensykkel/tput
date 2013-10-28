#ifndef __FILTER_H__
#define __FILTER_H__

#include <string>

using std::string;


/* Helper class to create a pcap filter string */
struct filter
{
	const char* src_addr;
	const char* src_port_first;
	const char* src_port_last;

	const char* dst_addr;
	const char* dst_port_first;
	const char* dst_port_last;

	bool include_reverse;

	filter()
		: src_addr(NULL), src_port_first(NULL), src_port_last(NULL),
		dst_addr(NULL), dst_port_first(NULL), dst_port_last(NULL),
		include_reverse( false )
	{
	};

	std::string str() const;
	static bool validate_port(const std::string& port);
	static bool validate_host(const std::string& host);
};

#endif
