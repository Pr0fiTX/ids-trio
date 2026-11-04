#ifndef PARSER_H
#define PARSER_H

typedef enum{
    ACTION_ALERT,
    ACTION_DROP
} TypeAction;

typedef enum{
    PROTO_TCP,
    PROTO_UPD,
    PROTO_ICMP,
    PROTO_ANY
}ProtocolType;

typedef struct {
    int rule_id;
    TypeAction action;
    ProtocolType protocol;
    char st_ip[16];
    int st_port;
    char fi_ip[16];
    int fi_port;
    char signature[256];
    char mes[256];
}Rule;

// Вводим функцию читающую правила из файл txt
int read_rules(const char *filepars, Rule *rules, int max_num);

// Функция которая будет анализировать полученные от ядра пакеты с помощью считанных правил
void analyze_packet(const Rule *rules, int count_rules);

#endif