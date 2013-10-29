#include <pcap.h>
#include "stream.h"
#include "filter.h"
#include <tr1/cstdint>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <signal.h>
#include <getopt.h>
#include <map>
#include <vector>

using std::string;
using std::map;
using std::vector;



static int caught_signal = 0;



static void signal_handler(int signal)
{
	caught_signal = signal;
}



#define usecs(t) (((uint64_t) t.tv_sec) * 1000000 + ((uint64_t) t.tv_usec))
//static inline uint64_t usecs(struct timeval& t)
//{
//	return t.tv_sec * 1000000 + t.tv_usec;
//}



uint64_t calculate_throughput(pcap_t* handle, unsigned slice_interval)
{
	pcap_pkthdr* hdr;
	const u_char* pkt;

	const uint64_t t_slice = slice_interval * 1000;

	uint64_t first = 0;
	uint64_t slice_idx = 0;

	while (!caught_signal && pcap_next_ex(handle, &hdr, &pkt) == 1)
	{
		uint64_t next = usecs(hdr->ts);
		if (next >= (first + t_slice))
		{
			++slice_idx;
			first = next;
		}

		uint32_t tcp_off = (*((uint8_t*) pkt + ETHERNET_FRAME_LEN) & 0x0f) * 4; // IP header size (= offset to IP payload)
		uint32_t src = *((uint32_t*) (pkt + ETHERNET_FRAME_LEN + 12)); // IP source address
		uint32_t dst = *((uint32_t*) (pkt + ETHERNET_FRAME_LEN + 16)); // IP destination address

		uint16_t sport = *((uint16_t*) (pkt + ETHERNET_FRAME_LEN + tcp_off)); // TCP source port
		uint16_t dport = *((uint16_t*) (pkt + ETHERNET_FRAME_LEN + tcp_off + 2)); // TCP destination port

		slice& slice = lookup_stream_slices(src, dst, sport, dport, slice_idx).at(slice_idx);
		slice.total_bytes += hdr->len;
		slice.total_pkts += 1;
		// TODO: packets with payload (need to look at TCP size header field)
	}

	return slice_idx + 1;
}



int set_filter(pcap_t* handle, const filter& options)
{
	bpf_program prog_code;

	if (pcap_compile(handle, &prog_code, options.str().c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
	{
		return -1;
	}

	if (pcap_setfilter(handle, &prog_code) == -1)
	{
		pcap_freecode(&prog_code);
		return -2;
	}

	pcap_freecode(&prog_code);
	return 0;
}



int main(int argc, char** argv)
{
	filter options;
	unsigned time_slice = DEFAULT_TIME_SLICE;
	char* output_filename = NULL;
	FILE* output_file = stdout;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = NULL;

	bool packet_count = false;

	int status = 0;
	uint64_t num_slices = 0;

	// Parse command line options
	int opt;
	while ((opt = getopt(argc, argv, ":hs:q:Q:r:p:P:t:o:ac")) != -1)
	{
		switch (opt)
		{
			case '?':
				// Unknown option
				fprintf(stderr, "Warning: Unknown option -%c\n", optopt);
				break;

			case ':':
				// Missing argument
				fprintf(stderr, "Error: Option -%c requires a parameter\n", optopt);
				status = ':';
				goto give_usage;

			case 'h':
				// Show help and quit
				goto give_usage;

			case 's':
				// Filter on source IP address
				if (!filter::validate_host(optarg))
				{
					fprintf(stderr, "Error: Option -s requires a valid hostname\n");
					status = 's';
					goto give_usage;
				}

				options.src_addr = optarg;
				break;

			case 'q':
				// Filter on source port
				if (!filter::validate_port(optarg))
				{
					fprintf(stderr, "Error: Option -q requires a valid port number\n");
					status = 'q';
					goto give_usage;
				}

				options.src_port_first = optarg;
				break;

			case 'Q':
				// Last port in source port range
				if (!filter::validate_port(optarg))
				{
					fprintf(stderr, "Error: Option -Q requires a valid port number\n");
					status = 'Q';
					goto give_usage;
				}

				options.src_port_last = optarg;
				break;

			case 'r':
				// Filter on receiver IP address
				if (!filter::validate_host(optarg))
				{
					fprintf(stderr, "Error: Option -r requires a valid hostname\n");
					status = 'r';
					goto give_usage;
				}

				options.dst_addr = optarg;
				break;

			case 'p':
				// Filter on destination port
				if (!filter::validate_port(optarg))
				{
					fprintf(stderr, "Error: Option -p requires a valid port number\n");
					status = 'p';
					goto give_usage;
				}

				options.dst_port_first = optarg;
				break;

			case 'P':
				// Last port in destination port range
				if (!filter::validate_port(optarg))
				{
					fprintf(stderr, "Error: Option -P requires a valid port number\n");
					status = 'P';
					goto give_usage;
				}

				options.dst_port_last = optarg;
				break;

			case 't':
				{
					// Aggregate over time slice
					char* str = NULL;
					time_slice = strtoul(optarg, &str, 10);
					if (time_slice < 1 || str == NULL || *str != '\0')
					{
						fprintf(stderr, "Error: Option -t requires a number of seconds\n");
						status = 't';
						goto give_usage;
					}
					else if (time_slice > 60000)
					{
						fprintf(stderr, "Warning: Time slice is set to over one minute\n");
					}
				}
				break;

			case 'o':
				// Write to file instead of stdout
				output_filename = optarg;
				break;

			case 'a':
				// Include reverse filter (to count ACKs as well)
				options.include_reverse = true;
				break;

			case 'c':
				// Show packet count instead of byte count
				packet_count = true;
				break;

		}
	}


	// Try to open pcap file
	if (optind == argc)
	{
		fprintf(stderr, "Error: No trace file specified\n");
		status = 1;
		goto give_usage;
	}

	if ((handle = pcap_open_offline(argv[optind], errbuf)) == NULL)
	{
		fprintf(stderr, "Error: %s\n", errbuf);
		return 1;
	}
	
	fprintf(stderr, "Analyzing trace file: %s\n", argv[optind]);

	// Set pcap filter
	if (set_filter(handle, options) < 0)
	{
		pcap_perror(handle, (char*) "Error");
		return 2;
	}
	
	fprintf(stderr, "Using filter: %s\n", options.str().c_str());

	// Open output file
	if (output_filename != NULL)
	{
		if ((output_file = fopen(output_filename, "w")) == NULL)
		{
			fprintf(stderr, "Error: Couldn't open output file\n");
			return 'o';
		}
	}

	// Calculate throughput per stream
	if (signal(SIGINT, &signal_handler) == SIG_ERR)
	{
		fprintf(stderr, "Error: Couldn't register signal handler\n");
		return 3;
	}

	num_slices = calculate_throughput(handle, time_slice);

	if (!caught_signal)
	{
		// Write header row
		fprintf(output_file, "%48c%9d", ' ', 1);

		for (uint64_t i = 2; i < num_slices; ++i)
			fprintf(output_file, ", %9lu", i);

		fprintf(output_file, "\n");

		// Write results to CSV file
		for (maptype::iterator stream = connection_map.begin(); !caught_signal && stream != connection_map.end(); stream++)
		{
			fprintf(output_file, "%46s", stream->first.str().c_str());

			uint64_t i, n;
			for (i = 1, n = stream->second.size(); !caught_signal && i < n; ++i)
			{
				if (packet_count)
					fprintf(output_file, ", %9lu", stream->second[i].total_pkts);
				else
					fprintf(output_file, ", %9lu", stream->second[i].total_bytes);
			}

			if (n != num_slices) 
			{
				fprintf(stderr, "Warning: stream %s has %lu slices, but there should be %lu, padding the remaining\n", stream->first.str().c_str(), n, num_slices);

				while (n++ < num_slices)
					fprintf(output_file, ", %9d", 0);
			}
			
			fprintf(output_file, "\n");
		}
	}

	// Clean up and exit
	pcap_close(handle);

	if (output_filename != NULL)
		fclose(output_file);

	return 0;


give_usage:
	fprintf(stderr,
			"Usage: %s [-h] [options] trace-file\n"
			"Options:\n"
			"  -h\tPrint this help and quit\n"
			"  -s\tSource IP address\n"
			"  -q\tSource start port\n"
			"  -Q\tSource end port\n"
			"  -r\tDestination IP address\n"
			"  -p\tDestination start port\n"
			"  -P\tDestination end port\n"
			"  -t\tAggregate throughput samples over a number of milliseconds (defaults to %d)\n"
			"  -o\tWrite throughput samples to file instead of stdout\n"
			"  -a\tInclude the reverse streams\n"
			"  -c\tShow TCP segment count instead of byte count\n"
			"\n", argv[0], DEFAULT_TIME_SLICE);

	return status;
}
