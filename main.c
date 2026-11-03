#include "core.h"
#include "parser.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  char *dev = "eth0";

  // Флаг для указания сетевого интерфейса
  if (argc == 2) {
    dev = argv[1];
  }

  printf("=> Запуска перехватчика ids-trio...\n");

  if (start_capture(dev) != 0) {
    fprintf(stderr, "!> Не получилось перехватить пакеты! Завершение...\n");
    return 1;
  }
  return 0;
}
