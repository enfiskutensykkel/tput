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

	uint32_t src;		// Connection source address
	uint32_t dst;		// Connection destination address
	uint16_t sport;		// Connection source port
	uint16_t dport;		// Connection destination port
};


/* A slice object */
struct slice
{
	uint64_t total_bytes;		// total byte count (including headers)
	uint64_t total_pkts;		// total TCP segment count
	//uint64_t num_payload_pkts;	// number of TCP segments with payload

	slice()
		: total_bytes(0), total_pkts(0)//, num_payload_pkts(0)
	{
	};

	slice(uint64_t bytes, uint64_t pkts) //, uint64_t payload_pkts)
		: total_bytes(bytes), total_pkts(pkts)//, num_payload_pkts(payload_pkts)
	{
	};
};


/* Connection-to-slice map type */
typedef std::map< stream, std::vector<slice> > maptype;


/* Connection-to-slice map */
extern maptype connection_map;

/* Get a connection's slices */
std::vector<slice>& lookup_stream_slices(uint32_t src_addr, uint32_t dst_addr, uint16_t src_port, uint16_t dst_port, uint64_t expected_slice_count);

#endif
