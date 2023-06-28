#include <pcap.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    pcap_t *handle;			/* session handle */
    char *dev;			/* the device to sniff on */
    char errbuf[pcap_errbuf_size];	/* error string */
    struct bpf_program fp;		/* the compiled filter */
    char filter_exp[] = "port 23";	/* the filter expression */
    bpf_u_int32 mask;		/* our netmask */
    bpf_u_int32 net;		/* our ip */
    struct pcap_pkthdr header;	/* the header that pcap gives us */
    const u_char *packet;		/* the actual packet */

    /* define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == null) {
        fprintf(stderr, "couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* open the session in promiscuous mode */
    handle = pcap_open_live(dev, bufsiz, 1, 1000, errbuf);
    if (handle == null) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    /* grab a packet */
    packet = pcap_next(handle, &header);
    /* print its length */
    printf("jacked a packet with length of [%d]\n", header.len);
    /* and close the session */
    pcap_close(handle);
    return(0);
}