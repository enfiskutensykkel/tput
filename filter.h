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

	filter()
		: src_addr(NULL), src_port_first(NULL), src_port_last(NULL),
		dst_addr(NULL), dst_port_first(NULL), dst_port_last(NULL)
	{
	};

	string str()
	{
		// Add protocol to filter
		string filter("tcp");

		// Add source host to filter
		if (src_addr)
			filter += " and src host " + string(src_addr);

		// Add destination host filter
		if (dst_addr)
			filter += " and dst host " + string(dst_addr);

		// Add source ports to filter
		if (src_port_first)
		{
			if (src_port_last)
			{
				filter += " and src portrange " + string(src_port_first) + "-" + string(src_port_last);
			}
			else
				filter += " and src port " + string(src_port_first);
		}

		// Add destination ports to filter
		if (dst_port_first)
		{
			if (dst_port_last)
			{
				filter += " and dst portrange " + string(dst_port_first) + "-" + string(dst_port_last);
			}
			else
				filter += " and dst port " + string(dst_port_first);
		}

		return filter;
	};
};

#endif
