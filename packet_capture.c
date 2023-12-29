#include <pcap.h>
#include <stdio.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    pcap_dump(user_data, pkthdr, packet);
}

int main() {
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_dumper_t *dumper;
    const char *filename = "packets_data.pcap";  // Output file

    // Retrieve the device list
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return(2);
    }

    // Check if the list is empty
    if (alldevs == NULL) {
        fprintf(stderr, "No devices found. Make sure you have the necessary permissions.\n");
        return(2);
    }

    // Use the first device in the list
    device = alldevs;

    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        pcap_freealldevs(alldevs);
        return(2);
    }

    // Open file to write packets
    dumper = pcap_dump_open(handle, filename);
    if (dumper == NULL) {
        fprintf(stderr, "Couldn't open file for packet dump: %s\n", filename);
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return(2);
    }

    // Free the device list
    pcap_freealldevs(alldevs);

    // Capture packets and write them to the file
    pcap_loop(handle, -1, packet_handler, (u_char *)dumper);

    pcap_dump_close(dumper);
    pcap_close(handle);

    printf("Packet capturing complete. Data saved to %s\n", filename);
    return 0;
}
