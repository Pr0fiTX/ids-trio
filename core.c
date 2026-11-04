#include "core.h"
#include <stdio.h>
#include <stdlib.h>

// Подключенные в HEADER
// pcap.h
// stdint.h
void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet) {
  // TODO:
  printf("=> Обработан пакет с длинной %d\n", header->len);
}

int start_capture(const char *device) {
  char err_buffer[PCAP_ERRBUF_SIZE];
  pcap_t *net_stream = NULL;

  net_stream = pcap_open_live(device, BUFSIZ, 1, 1000, err_buffer);
  if (net_stream == NULL) {
    fprintf(stderr, "!> Не получилось перехватить пакеты с устройства %s: %s\n",
            device, err_buffer);
    return -1;
  }

  printf("=> Прослушиваем устройство %s...\n", device);

  if (pcap_loop(net_stream, 0, packet_handler, NULL) < 0) {
    fprintf(stderr, "!> pcap_loop(): ошибка: %s\n", err_buffer);
    return -1;
  }

  pcap_close(net_stream);
  return 0;
}
