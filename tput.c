#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <stdint.h>
#include <signal.h>

struct filter
{
	const char* protocol;

	const char* src_hostname;
	const char* src_first_port;
	const char* src_last_port;

	const char* dst_hostname;
	const char* dst_first_port;
	const char* dst_last_port;
};

static int caught_signal = 0;



void calculate_throughput(pcap_t* handle, long time_slice, FILE* output_file)
{
	struct pcap_pkthdr* hdr;
	const u_char* pkt;
	struct timeval first = {0, 0};
	uint64_t bytes = 0;

	while (!caught_signal && pcap_next_ex(handle, &hdr, &pkt) == 1)
	{
		if (hdr->ts.tv_sec >= first.tv_sec + time_slice)
		{
			fprintf(output_file, "%lu\n", bytes);
			first = hdr->ts;
			bytes = 0;
		}

		bytes += hdr->len;
	}

	if (bytes > 0)
	{
		fprintf(output_file, "%lu\n", bytes);
	}

	fflush(output_file);
}



int set_filter(pcap_t* handle, struct filter* filter, char* filterstr, size_t filterstrlen)
{
	struct bpf_program progcode;
	
	// Filter on protocol
	memset(filterstr, 0, filterstrlen);
	snprintf(filterstr, filterstrlen, "%s", filter->protocol);

	// Filter on hostname if set
	if (filter->src_hostname)
	{
		strncat(filterstr, " and src host ", filterstrlen-1);
		strncat(filterstr, filter->src_hostname, filterstrlen-1);
	}

	if (filter->dst_hostname)
	{
		strncat(filterstr, " and dst host ", filterstrlen-1);
		strncat(filterstr, filter->dst_hostname, filterstrlen-1);
	}

	// Filter on ports if set
	if (filter->src_first_port)
	{
		strncat(filterstr, " and src ", filterstrlen-1);

		if (filter->src_last_port)
		{
			strncat(filterstr, " portrange ", filterstrlen-1);
			strncat(filterstr, filter->src_first_port, filterstrlen-1);
			strncat(filterstr, "-", filterstrlen-1);
			strncat(filterstr, filter->src_last_port, filterstrlen-1);
		}
		else
		{
			strncat(filterstr, " port ", filterstrlen-1);
			strncat(filterstr, filter->src_first_port, filterstrlen-1);
		}
	}

	if (filter->dst_first_port)
	{
		strncat(filterstr, " and dst ", filterstrlen-1);

		if (filter->dst_last_port)
		{
			strncat(filterstr, "portrange ", filterstrlen-1);
			strncat(filterstr, filter->dst_first_port, filterstrlen-1);
			strncat(filterstr, "-", filterstrlen-1);
			strncat(filterstr, filter->dst_last_port, filterstrlen-1);
		}
		else
		{
			strncat(filterstr, "port ", filterstrlen-1);
			strncat(filterstr, filter->dst_first_port, filterstrlen-1);
		}
	}


	// Compile and set filter
	if (pcap_compile(handle, &progcode, filterstr, 0, PCAP_NETMASK_UNKNOWN) == -1)
	{
		return -1;
	}

	if (pcap_setfilter(handle, &progcode) == -1)
	{
		pcap_freecode(&progcode);
		return -2;
	}

	pcap_freecode(&progcode);
	return 0;
}



static inline
int validate_host(const char* hostname)
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



void signal_handler(int signal)
{
	caught_signal = signal;
}





int main(int argc, char** argv)
{
	struct filter options = { "tcp", NULL, NULL, NULL, NULL, NULL, NULL };
	unsigned time_slice = DEFAULT_TIME_SLICE;
	FILE* out = stdout;

	int status = 0;

	/* Parse command line options */
	int opt; char* str;
	while ((opt = getopt(argc, argv, ":hs:q:Q:r:p:P:t:f:")) != -1)
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

				options.src_hostname = optarg;
				break;

			case 'q':
				if (validate_port(optarg) < 0)
				{
					fprintf(stderr, "Error: Option -q requires a valid port number\n");
					status = 'q';
					goto give_usage;
				}

				options.src_first_port = optarg;
				break;

			case 'Q':
				if (validate_port(optarg) < 0)
				{
					fprintf(stderr, "Error: Option -Q requires a valid port number\n");
					status = 'Q';
					goto give_usage;
				}

				options.src_last_port = optarg;
				break;

			case 'r':
				if (validate_host(optarg) < 0)
				{
					fprintf(stderr, "Error: Option -r requires a valid hostname\n");
					status = 'r';
					goto give_usage;
				}

				options.dst_hostname = optarg;
				break;

			case 'p':
				if (validate_port(optarg) < 0)
				{
					fprintf(stderr, "Error: Option -p requires a valid port number\n");
					status = 'p';
					goto give_usage;
				}

				options.dst_first_port = optarg;
				break;

			case 'P':
				if (validate_port(optarg) < 0)
				{
					fprintf(stderr, "Error: Option -P requires a valid port number\n");
					status = 'P';
					goto give_usage;
				}

				options.dst_last_port = optarg;
				break;

			case 't':
				str = NULL;
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
				break;

			case 'f':
				if ((out = fopen(optarg, "w")) == NULL)
				{
					fprintf(stderr, "Error: Couldn't open output file\n");
					status = 'f';
					goto give_usage;
				}
				break;
		}
	}

	/* Try to open pcap file */
	if (optind == argc)
	{
		fprintf(stderr, "Error: No packet trace file specified\n");
		status = 1;
		goto give_usage;
	}

	pcap_t* handle = NULL;
	if ((handle = pcap_open_offline(argv[optind], NULL)) == NULL)
	{
		fprintf(stderr, "Error: Couldn't open packet trace file\n");
		status = 1;
		goto give_usage;
	}
	fprintf(stderr, "Analyzing trace file: %s\n", argv[optind]);

	/* Create and set filter */
	char filter[1024]; 
	if (set_filter(handle, &options, filter, sizeof(filter)) < 0)
	{
		pcap_perror(handle, "Error");
		exit(2);
	}
	fprintf(stderr, "Using filter: %s\n", filter);

	/* Calculate throughput */
	if (signal(SIGINT, &signal_handler) == SIG_ERR)
	{
		fprintf(stderr, "Error: Couldn't register signal handler\n");
		exit(3);
	}
	calculate_throughput(handle, time_slice, out);

	/* Clean up and exit */
	pcap_close(handle);
	fclose(out);
	exit(0);

give_usage:
	fprintf(stderr, 
			"Usage: %s [-h] [options] packettrace\n"
			"Options:\n"
			"  -h\tPrint this help and quit\n"
			"  -s\tSource IP address\n"
			"  -q\tSource start port\n"
			"  -Q\tSource end port\n"
			"  -r\tDestination IP address\n"
			"  -p\tDestination start port\n"
			"  -P\tDestination end port\n"
			"  -t\tAggregate results over a number of seconds (defaults to %d)\n"
			"  -f\tWrite results to file instead of stdout\n"
			"\n", argv[0], DEFAULT_TIME_SLICE);

	exit(status);
}
