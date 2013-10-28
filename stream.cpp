#include "stream.h"
#include <vector>
#include <map>
#include <tr1/cstdint>
#include <arpa/inet.h>
#include <sstream>

using std::map;
using std::vector;


typedef map< stream, vector<uint64_t> > mtype;


/* A map over all the connections */
mtype connection_map;


/* Helper function to find a connection or create it if it doesn't exist */
static inline
vector<uint64_t>& lookup_stream(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport)
{
	stream key(src, dst, sport, dport);
	mtype::iterator lower_bound = connection_map.lower_bound(key);

	if (lower_bound != connection_map.end() && !(connection_map.key_comp()(key, lower_bound->first)))
	{
		return lower_bound->second;
	}

	vector<uint64_t> nothing;
	mtype::iterator elem = connection_map.insert(lower_bound, mtype::value_type(key, nothing));
	return elem->second;
}



vector<uint64_t>& lookup_stream_samples(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport, uint64_t slices)
{
	vector<uint64_t>& samples = lookup_stream(src, dst, sport, dport);

	uint64_t size = samples.size();

	while (size <= slices)
	{
		samples.push_back(0);
		++size;
	}

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

	info.addr = src;
	connstr << ((int) info.str[0]);
	connstr << ".";
	connstr << ((int) info.str[1]);
	connstr << ".";
	connstr << ((int) info.str[2]);
	connstr << ".";
	connstr << ((int) info.str[3]);
	connstr << ":";
	connstr << ntohs(sport);

	connstr << "=>";

	info.addr = dst;
	connstr << ((int) info.str[0]);
	connstr << ".";
	connstr << ((int) info.str[1]);
	connstr << ".";
	connstr << ((int) info.str[2]);
	connstr << ".";
	connstr << ((int) info.str[3]);
	connstr << ":";
	connstr << ntohs(dport);

	return connstr.str();
}
