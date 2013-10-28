#include "filter.h"
#include <string>
#include <cstdlib>

using std::string;



bool filter::validate_host(const string& host)
{
	// TODO: Implement this
	return true;
}



bool filter::validate_port(const string& port)
{
	char* str = NULL;
	if (strtoul(port.c_str(), &str, 0) > 0xffff || str == NULL || *str != '\0')
	{
		return false;
	}

	return true;
}



string filter::str() const
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
}
