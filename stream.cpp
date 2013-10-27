#include "stream.h"
#include <vector>
#include <map>
#include <tr1/cstdint>

using std::map;
using std::vector;


/* A map over all the connections */
map<stream, vector<uint64_t> > connection_map;



/* Find a connection or create it if it doesn't exist */
vector<uint64_t>& lookup_stream(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport, uint64_t slices)
{
	map<stream, vector<uint64_t> >::iterator found;

	// Try to find connection in map	
	found = connection_map.find( stream(src, dst, sport, dport) );
	if ( found != connection_map.end() )
	{
		return found->second;
	}

	// No entry was found, register a new connection
	vector<uint64_t>& samples = connection_map[stream(src, dst, sport, dport)];
	while (slices--)
	{
		samples.push_back(0);
	}
	samples.push_back(0);

	return samples;
}



bool stream::operator<(const stream& rhs) const
{
	if (src < rhs.src)
		return true;
	if (src > rhs.src)
		return false;

	if (dst < rhs.dst)
		return true;
	if (dst > rhs.dst)
		return false;

	if (sport < rhs.sport)
		return true;
	if (sport > rhs.sport)
		return false;

	if (dport < rhs.dport)
		return true;
	if (dport > rhs.dport)
		return false;

	return false;
}



stream::stream(const stream& rhs)
{
	*this = rhs;
}



stream& stream::operator=(const stream& rhs)
{
	this->src = rhs.src;
	this->dst = rhs.dst;
	this->sport = rhs.sport;
	this->dport = rhs.dport;

	return *this;
}



string stream::str() const
{

	union 
	{
		uint32_t addr;
		uint8_t str[4];
	} info;

	ostringstream connstr;

	info.addr = ntohl(src);
	connstr << ((int) info.str[0]);
	connstr << ((int) info.str[1]);
	connstr << ((int) info.str[2]);
	connstr << ((int) info.str[3]);
	connstr << ":";
	connstr << ntohs(sport);

	connstr << "=>";

	info.addr = ntohl(dst);
	connstr << ((int) info.str[0]);
	connstr << ((int) info.str[1]);
	connstr << ((int) info.str[2]);
	connstr << ((int) info.str[3]);
	connstr << ":";
	connstr << ntohs(dport);

	return connstr.str();
}
