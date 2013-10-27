#ifndef __STREAM_H__
#define __STREAM_H__

#include <tr1/cstdint>
#include <vector>
#include <map>

/* A connection key */
struct stream
{
	bool operator<(const stream& rhs) const
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
	};

	stream(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport)
		: src( src ), dst( dst ), sport( sport ), dport( dport )
	{
	};

	stream(const stream& rhs)
	{
		*this = rhs;
	};

	stream& operator=(const stream& rhs)
	{
		this->src = rhs.src;
		this->dst = rhs.dst;
		this->sport = rhs.sport;
		this->dport = rhs.dport;

		return *this;
	};

	uint32_t src;
	uint32_t dst;
	uint16_t sport;
	uint16_t dport;
};


/* Connection map */
extern std::map<stream, std::vector<uint64_t> > connection_map;

/* Get a connection */
std::vector<uint64_t>& lookup_stream(uint32_t src_addr, uint32_t dst_addr, uint16_t src_port, uint16_t dst_port, uint64_t slices);

#endif
