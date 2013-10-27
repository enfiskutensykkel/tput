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


static inline
uint64_t usecs(struct timeval& t)
{
	static long first_second = -1;

	if (first_second == -1)
		first_second = t.tv_sec;

	return (t.tv_sec - first_second) * 1000000 + t.tv_usec;
}



uint64_t calculate_throughput(pcap_t* handle, unsigned time_slice)
{
	pcap_pkthdr* hdr;
	const u_char* pkt;

	uint64_t first = 0;
	uint64_t slice = 0;
	uint64_t next;

	uint32_t tcp_off;
	uint32_t src, dst;
	uint16_t sport, dport;

	while (!caught_signal && pcap_next_ex(handle, &hdr, &pkt) == 1)
	{
		next = usecs(hdr->ts);
		if (next >= first + time_slice)
		{
			++slice;
			first = next;

			for (map<stream, vector<uint64_t> >::iterator i = connection_map.begin(); i != connection_map.end(); i++)
			{
				i->second.push_back(0);
			}
		}

		
		tcp_off = (*((uint8_t*) pkt + ETHERNET_FRAME_LEN) & 0x0f) * 4; // IP header size (= offset to IP payload)
		src = *((uint32_t*) (pkt + ETHERNET_FRAME_LEN + 12)); // IP source address
		dst = *((uint32_t*) (pkt + ETHERNET_FRAME_LEN + 16)); // IP destination address

		sport = *((uint16_t*) (pkt + ETHERNET_FRAME_LEN + tcp_off)); // TCP source port
		dport = *((uint16_t*) (pkt + ETHERNET_FRAME_LEN + tcp_off + 2)); // TCP destination port

		vector<uint64_t>& stream = lookup_stream(src, dst, sport, dport, slice);
		stream[slice] += hdr->len;
	}

	return slice;
}



static
void signal_handler(int signal)
{
	caught_signal = signal;
}



static inline
int validate_host(const char* host)
{
	// TODO: Implement this
	return 0;
}



static inline
int validate_port(const char* port)
{
	char* str = NULL;
	if (strtoul(port, &str, 0) > 0xffff || str == NULL || *str != '\0')
	{
		return -1;
	}

	return 0;
}



int set_filter(pcap_t* handle, filter& options)
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
	FILE* output_file = stdout;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = NULL;

	int status = 0;
	uint64_t num_slices = 0;

	// Parse command line options
	int opt;
	while ((opt = getopt(argc, argv, ":hs:q:Q:r:p:P:t:o:")) != -1)
	{
		switch (opt)
		{
			case '?':
				fprintf(stderr, "Warning: Unknown option -%c\n", optopt);
				break;

			case ':':
				fprintf(stderr, "Error: Option -%c requires a parameter\n", optopt);
				status = ':';
				goto give_usage;

			case 'h':
				goto give_usage;

			case 's':
				if (validate_host(optarg) < 0)
				{
					fprintf(stderr, "Error: Option -s requires a valid hostname\n");
					status = 's';
					goto give_usage;
				}

				options.src_addr = optarg;
				break;

			case 'q':
				if (validate_port(optarg) < 0)
				{
					fprintf(stderr, "Error: Option -q requires a valid port number\n");
					status = 'q';
					goto give_usage;
				}

				options.src_port_first = optarg;
				break;

			case 'Q':
				if (validate_port(optarg) < 0)
				{
					fprintf(stderr, "Error: Option -Q requires a valid port number\n");
					status = 'Q';
					goto give_usage;
				}

				options.src_port_last = optarg;
				break;

			case 'r':
				if (validate_host(optarg) < 0)
				{
					fprintf(stderr, "Error: Option -r requires a valid hostname\n");
					status = 'r';
					goto give_usage;
				}

				options.dst_addr = optarg;
				break;

			case 'p':
				if (validate_port(optarg) < 0)
				{
					fprintf(stderr, "Error: Option -p requires a valid port number\n");
					status = 'p';
					goto give_usage;
				}

				options.dst_port_last = optarg;
				break;

			case 'P':
				if (validate_port(optarg) < 0)
				{
					fprintf(stderr, "Error: Option -P requires a valid port number\n");
					status = 'P';
					goto give_usage;
				}

				options.dst_port_last = optarg;
				break;

			case 't':
				{
					char* str = NULL;
					time_slice = strtoul(optarg, &str, 10);
					if (time_slice < 1 || str == NULL || *str != '\0')
					{
						fprintf(stderr, "Error: Option -t requires a number of seconds\n");
						status = 't';
						goto give_usage;
					}
					else if (time_slice > 60)
					{
						fprintf(stderr, "Warning: Time slice is set to over one minute\n");
					}
				}
				break;

			case 'o':
				if ((output_file = fopen(optarg, "w")) == NULL)
				{
					fprintf(stderr, "Error: Couldn't open output file\n");
					status = 'o';
					goto give_usage;
				}
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
		fprintf(output_file, "%d", 1);
		for (uint64_t i = 2; i <= num_slices; ++i)
			fprintf(output_file, ", %lu", i);
		fprintf(output_file, "\n");

		// Write results to CSV file
		for (map<stream, vector<uint64_t> >::iterator stream = connection_map.begin(); stream != connection_map.end(); stream++)
		{
			
			fprintf(output_file, "%s", stream->first.str().c_str());

			uint64_t i, n;
			for (i = 1, n = stream->second.size(); i < n; ++i)
			{
				fprintf(output_file, ", %lu", stream->second[i]);
			}

			while (n++ < num_slices)
			{
				fprintf(output_file, ", 0");
			}

			fprintf(output_file, "\n");
		}
	}

	// Clean up and exit
	pcap_close(handle);
	fclose(output_file);
	return 0;


give_usage:
	fprintf(stderr,
			"Usage: %s [-h] [options] trace-file\n"
			"Options:\n"
			" -h\tPrint this help and quit\n"
			" -s\tSource IP address\n"
			" -q\tSource start port\n"
			" -Q\tSource end port\n"
			" -r\tDestination IP address\n"
			" -p\tDestination start port\n"
			" -P\tDestination end port\n"
			" -t\tAggregate results over a number of milliseconds (defaults to %d)\n"
			" -o\tWrite results to file instead of stdout\n"
			"\n", argv[0], DEFAULT_TIME_SLICE);

	return status;
}
