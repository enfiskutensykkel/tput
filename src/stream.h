#ifndef __STREAM_H__
#define __STREAM_H__

#include <tr1/cstdint>
#include <vector>
#include <map>
#include <string>

using std::string;
using std::ostringstream;


/* A connection key */
struct stream
{
	bool operator<(const stream& rhs) const;

	stream(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport)
		: src( src ), dst( dst ), sport( sport ), dport( dport )
	{
	};

	stream(const stream& rhs);

	stream& operator=(const stream& rhs);

	string str() const;

	uint32_t src;
	uint32_t dst;
	uint16_t sport;
	uint16_t dport;
};


/* Connection map */
extern std::map<stream, std::vector<uint64_t> > connection_map;

/* Get a connection */
std::vector<uint64_t>& lookup_stream_samples(uint32_t src_addr, uint32_t dst_addr, uint16_t src_port, uint16_t dst_port, uint64_t expected_samples);

#endif
