#include "stream.h"
#include <vector>
#include <map>
#include <cstdint>
#include <arpa/inet.h>
#include <sstream>

using std::map;
using std::vector;



/* A map over all the connections */
maptype connection_map;


/* Helper function to find a connection or create it if it doesn't exist */
    static inline
vector<slice>& lookup_stream(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport)
{
    stream key(src, dst, sport, dport);
    maptype::iterator lower_bound = connection_map.lower_bound(key);

    if (lower_bound != connection_map.end() && !(connection_map.key_comp()(key, lower_bound->first)))
    {
        return lower_bound->second;
    }

    vector<slice> empty;
    maptype::iterator elem = connection_map.insert(lower_bound, maptype::value_type(key, empty));
    return elem->second;
}



vector<slice>& lookup_stream_slices(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport, uint64_t curr_slice_idx)
{
    vector<slice>& slices = lookup_stream(src, dst, sport, dport);

    uint64_t count = slices.size();

    while (count <= curr_slice_idx)
    {
        //slices.push_back(slice(0, 0, 0));
        slices.push_back(slice(0, 0));
        ++count;
    }

    return slices;
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
