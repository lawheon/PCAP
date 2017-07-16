
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>

int main()
{
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "port 80";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr *header;
	const u_char *packet;

	/*Define the device */
	dev = pcap_lookupdev(errbuf);
	if(dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return (2);
	}

	/*Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask= 0;
	}

	/*Open the session in promiscuous mod */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 0;
	}

	/*Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
		}

		if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 0;
		}
		/*Grab a packet */
		pcap_next_ex(handle, &header, &packet);

		/*Print */
		printf("Packet Capture %d bytes\n", header->len);
		for (int i = 0; i < header->len; i++)
		{
			if ((*(packet + i) & 0xff) >= 0x10)
			{
				printf("%x ", *(packet + i) & 0xff);
			}
			else
			{
				printf("0%x ", *(packet + i) & 0xff);
			}
			if (i % 16 == 15)
			{
				printf("\n");
			}
			else if (i % 8 == 7)
			{
				printf(" ");
			}
		}
		printf ("\n\n");
		printf ("Destination : ");
		for (int i = 0; i < 6; i++)
		{
			if ((*(packet + i) & 0xff) >= 0x10)
			{
				printf("%x ", *(packet + i) & 0xff);
			}
			else
			{
				printf("0%x ", *(packet + i) & 0xff);
			}
		
		}
		printf ("\n");
		printf ("Source : ");
		for (int i = 6; (5 < i && i < 12); i++)
		{
			if ((*(packet + i) & 0xff) >= 0x10)
			{
				printf("%x ", *(packet + i) & 0xff);
			}
			else
			{
				printf("0%x ", *(packet + i) & 0xff);
			}
		}
		printf ("\n");
		printf ("Type : ");
		for (int i = 12; (11 < i && i < 14); i++)
		{
			if ((*(packet + i) & 0xff) >= 0x10)
			{
				printf("%x ", *(packet + i) & 0xff);
			}
			else
			{
				printf("0%x ", *(packet + i) & 0xff);
			}
		}
		printf ("\n\n");
		printf ("IP_src : ");
		for (int i = 26; (25 < i && i < 30); i++)
		{
			if ((*(packet + i) & 0xff) >= 0x10)
			{
				printf("%d ", *(packet + i) & 0xff);
			}
			else
			{
				printf("%d ", *(packet + i) & 0xff);
			}
		}
		printf ("\n");
		printf ("IP_des : ");
		for (int i = 30; (29 < i && i < 34); i++)
		{
			if ((*(packet + i) & 0xff) >= 0x10)
			{
				printf("%d ", *(packet + i) & 0xff);
			}
			else
			{
				printf("%d ", *(packet + i) & 0xff);
			}
		}
		/*Close */
		printf("\n");
		pcap_close(handle);
		return(0);
	}
