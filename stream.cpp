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
