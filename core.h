#ifndef CORE_H
#define CORE_H

#include <pcap.h>
#include <stdint.h>

int start_capture(const char *device);
void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet);

#endif // CORE_H
