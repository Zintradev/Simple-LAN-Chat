#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "pcap.h"

typedef struct mac_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
} mac_address;

typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

mac_address MAC_origen  = {0x00,0x11,0x22,0x33,0x44,0x55}; // MAC genérica
mac_address MAC_destino = {0xff,0xff,0xff,0xff,0xff,0xff}; // broadcast genérico

ip_address IP_origen  = {192,168,0,100};     // IP genérica
ip_address IP_destino = {255,255,255,255};   // broadcast IP

uint16_t CalcularChecksum(uint8_t *packet, int length)
{
    uint16_t sum = 0;
    if (length%2 != 0)
    {
        length++;
        packet[length-1]=0x00;
    }
    for (int i=0; i<length; i=i+2)
    {
        uint16_t word = (packet[i] << 8) | packet[i+1];
        sum = sum + word;
        if (sum > 0xFFFF)
        {
            sum = sum + 1;
            sum = sum & 0xFFFF;
        }
    }
    return ~sum;
}

uint8_t msb(uint16_t d) { return (uint8_t)((d & 0xFF00)>>8); }
uint8_t lsb(uint16_t d) { return (uint8_t)(d & 0x00FF); }

int main(int argc, char **argv)
{
    pcap_if_t *all_NIC;
    pcap_if_t *my_NIC;
    int my_NIC_id;
    pcap_t *my_NIC_handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i=0;

    u_char packet[300];
    char alias[50];
    char mensaje[200];
    char datos[256];
    int numdatos;
    int fragmento_id=0;
    int sala;

    // Lista de adaptadores
    printf("\nAdaptadores (NIC) disponibles:\n");
    if (pcap_findalldevs(&all_NIC, errbuf) == -1)
    {
        fprintf(stderr,"ERROR: error en pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    for(my_NIC=all_NIC; my_NIC; my_NIC=(*my_NIC).next)
    {
        printf("%d. %s", ++i, (*my_NIC).name);
        if ((*my_NIC).description)
            printf(" (%s)\n", (*my_NIC).description);
        else
            printf(" (Descripcion no disponible)\n");
    }

    if(i==0)
    {
        printf("\nERROR: No se encuentran adaptadores NIC\n\n");
        return 2;
    }

    // Seleccionar el adaptador
    printf("Seleccionar el adaptador de interfaz NIC (1-%d):",i);
    scanf("%d", &my_NIC_id);
    if(my_NIC_id < 1 || my_NIC_id > i)
    {
        printf("\nERROR: Selección fuera de rango\n\n");
        pcap_freealldevs(all_NIC);
        return 3;
    }

    for(my_NIC=all_NIC, i=0; i< my_NIC_id-1 ;my_NIC=(*my_NIC).next, i++);

    if ((my_NIC_handle = pcap_open_live((*my_NIC).name,65536,1,1000,errbuf)) == NULL)
    {
        printf("\nERROR: No se puede abrir el adaptador NIC - %s\n", (*my_NIC).name);
        pcap_freealldevs(all_NIC);
        return 4;
    }

    // Pedir alias y sala
    printf("Alias de usuario: ");
    while(getchar() != '\n');
    fgets(alias,sizeof(alias),stdin);
    alias[strcspn(alias, "\n")] = 0;

    do {
        printf("Número de sala (1 a 10): ");
        scanf("%d", &sala);
    } while(sala < 1 || sala > 10);

    while (1)
    {
        printf("Mensaje: ");
        fgets(mensaje,sizeof(mensaje),stdin);
        mensaje[strcspn(mensaje, "\n")] = 0;

        sprintf(datos,"%s > %s", alias, mensaje);
        numdatos = (int)strlen(datos) + 2; // sala + string + null

        if(numdatos > 256)
        {
            printf("\nERROR: mensaje demasiado largo\n");
            continue;
        }

        // MAC destino
        memcpy(packet+0,&MAC_destino,6);
        // MAC origen
        memcpy(packet+6,&MAC_origen,6);
        // EtherType = IPv4
        packet[12]=0x08;
        packet[13]=0x00;
        // IPv4 header
        packet[14]=0x45;
        packet[15]=0x00;
        packet[16]=msb(20+numdatos);
        packet[17]=lsb(20+numdatos);
        packet[18]=msb(fragmento_id);
        packet[19]=lsb(fragmento_id);
        fragmento_id++;
        packet[20]=0x40;
        packet[21]=0x00;
        packet[22]=0x40;
        packet[23]=0xfd;
        packet[24]=0;
        packet[25]=0;
        memcpy(packet+26,&IP_origen,4);
        memcpy(packet+30,&IP_destino,4);

        // Checksum
        uint16_t c = CalcularChecksum(packet+14,20);
        packet[24] = msb(c);
        packet[25] = lsb(c);

        // Datos: sala + alias > mensaje
        packet[34] = (u_char)sala;
        memcpy(packet+35,datos,strlen(datos)+1);

        pcap_sendpacket(my_NIC_handle,packet,34+numdatos);

        printf("Mensaje enviado a sala %d.\n", sala);
    }

    pcap_close(my_NIC_handle);
    return 0;
}
