#include <stdio.h>
#include <string.h>
#include "parser.h"
#include <stdlib.h>

// Считываем правила из txt файла
int read_rules(const char *filepars, Rule *rules, int max_num){
    FILE *file = fopen(filepars, "r");
    if (file==NULL){
        printf("Ошибка открытия файла с правилами\n");
        return 0;
    }
    
    char line[512];
    int count=0;

    const char *delims = " \t->";

    while(fgets(line, sizeof(line), file)!=NULL && max_num > count){
        if (line[0]=='\n' || line[0] =='\r' || line[0] == '#'){
            continue;
        }
        
        // Отчистка от \n и \r
        line[strcspn(line, "\r\n")]=0;

        char *part =strtok(line, delims);

        if (part ==NULL) {
            continue;
        }

        // Загружаем действия
        if (strcmp(part, "alert") ==0){
            rules[count].action = ACTION_ALERT;
        }
        else if(strcmp(part,"drop")==0){
            rules[count].action=ACTION_DROP;
        }

        //Заполняем наш контейнер информацией о протоколах
        part =strtok(NULL,delims);
        if (part!=NULL){
            if (strcmp(part,"tcp")==0){
                rules[count].protocol=PROTO_TCP;
            }
            else if (strcmp(part,"udp")==0){
                rules[count].protocol=PROTO_UPD;
            }
            else if (strcmp(part,"icmp")){
                rules[count].protocol=PROTO_ICMP;
            }
            else{
                rules[count].protocol=PROTO_ANY;
            }
        }

        //Извлекаем ip источника
        part=strtok(NULL,delims);
        if (part!=NULL){
            strncpy(rules[count].st_ip, part, 15);
            rules[count].st_ip[15] ='\0';
        }
        
        //Извлекаем порт источника
        part=strtok(NULL,delims);
        if (part!=NULL){
            rules[count].st_port=atoi(part);
        }

        // Извлекаем ip получателя
        part=strtok(NULL,delims);
        if (part!=NULL){
            strncpy(rules[count].fi_ip, part, 15);
            rules[count].fi_ip[15] ='\0';
        }
        //Извлекаем порт получателя
        part=strtok(NULL,delims);
        if (part!=NULL){
            rules[count].fi_port=atoi(part);
        }

        part=strtok(NULL, delims);
        if (part!=NULL){
            strcpy(rules[count].signature, part,255);
            rules[count].signature[255]='\0';
        }
        
        // Присваиваем правилу порядковый номер
        rules[count].rule_id=count+1;
        count++;
    }
    fclose(file);

    printf("Правил загружено %d", count);
    return count;
}



/*!!!!!!!!!!!!! Packet это временная переменная нужно будет заменить на ту которую передаст ядро!!!!!!!!!!!!!!!!!!!*/

// Функция анализа
void analyze_packet(const Rule *rules, int count_rules, const Packet *packet) {
    // Запускаем цикл проверки пакета по всем загруженным правилам
    for (int i = 0; i < count_rules; i++) {
        
        //Проверка протокола
        if (rules[i].protocol != PROTO_ANY && rules[i].protocol != packet->protocol) {
            continue; 
        }

        //Проверка IP-адресов
        if (strcmp(rules[i].st_ip, "any") != 0 && strcmp(rules[i].st_ip, packet->st_ip) != 0) {
            continue;
        }
        if (strcmp(rules[i].fi_ip, "any") != 0 && strcmp(rules[i].fi_ip, packet->fi_ip) != 0) {
            continue;
        }

        // Проверка портов
        if (rules[i].st_port != 0 && rules[i].st_port != packet->st_port) {
            continue;
        }
        if (rules[i].fi_port != 0 && rules[i].fi_port != packet->fi_port) {
            continue;
        }

        // Паттерн матчинг
        if (strlen(rules[i].signature) > 0) {
            if (strstr(packet->payload, rules[i].signature) == NULL) {
                continue; 
            }
        }

        //Если дошло до сюда, то выполняем действие
        if (rules[i].action == ACTION_ALERT) {
            printf("[ВНИМАНИЕ] Обнаружена угроза по правилу %d: %s\n", rules[i].rule_id, rules[i].signature);
        } else if (rules[i].action == ACTION_DROP) {
            // Модуль IPS: активная блокировка пакета
            printf("[БЛОКИРОВКА] Пакет отброшен по правилу %d!\n", rules[i].rule_id);
        }
        
        return; 
    }
}

