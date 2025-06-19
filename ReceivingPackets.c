#include "pcap.h"
#include "time.h"

typedef struct mac_address {
    u_char byte1, byte2, byte3, byte4, byte5, byte6;
} mac_address;

typedef struct eth_type {
    u_char h;
    u_char l;
} eth_type;

typedef struct ip_address {
    u_char byte1, byte2, byte3, byte4;
} ip_address;

typedef struct ip_header {
    u_char  ver_ihl;
    u_char  tos;
    u_short tlen;
    u_short frag_id;
    u_short frag_flags_offset;
    u_char  ttl;
    u_char  protocol;
    u_short crc;
    ip_address saddr;
    ip_address daddr;
    u_int op_pad;
} ip_header;

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

uint16_t bytes_to_word(uint8_t h, uint8_t l)
{
    return (((uint16_t)h)<<8) + (uint16_t)l;
}

int main()
{
    pcap_if_t *all_NIC;
    pcap_if_t *my_NIC;
    int my_NIC_id, i=0, res;
    pcap_t *my_NIC_handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *packet;

    mac_address *smac, *dmac;
    eth_type *etype;
    ip_header *ih;
    ip_address *sip, *dip;

    int sala_usuario;
    printf("Número de sala (1 a 10): ");
    scanf("%d", &sala_usuario);

    printf("\nAdaptadores (NIC) disponibles:\n");
    if (pcap_findalldevs(&all_NIC, errbuf) == -1)
    {
        fprintf(stderr,"ERROR: %s\n", errbuf); return 1;
    }

    for(my_NIC=all_NIC; my_NIC; my_NIC=(*my_NIC).next)
    {
        printf("%d. %s", ++i, (*my_NIC).name);
        if ((*my_NIC).description)
            printf(" (%s)\n", (*my_NIC).description);
        else
            printf(" (Descripcion no disponible)\n");
    }

    printf("Seleccionar NIC (1-%d): ", i);
    scanf("%d", &my_NIC_id);
    for(my_NIC=all_NIC, i=0; i< my_NIC_id-1 ;my_NIC=(*my_NIC).next, i++);

    if ((my_NIC_handle = pcap_open_live((*my_NIC).name,65536,1,1000,errbuf)) == NULL)
    {
        printf("\nERROR: No se puede abrir el adaptador - %s\n", (*my_NIC).name);
        pcap_freealldevs(all_NIC);
        return 4;
    }

    printf("\nEsperando mensajes en sala %d...\n", sala_usuario);
    pcap_freealldevs(all_NIC);

    while((res = pcap_next_ex(my_NIC_handle, &header, &packet)) >= 0)
    {
        if(res == 0) continue;

        dmac = (mac_address *) (packet+ 0);
        smac = (mac_address *) (packet+ 6);
        etype = (eth_type *) (packet+ 12);

        if (((*etype).h == 0x08)&&((*etype).l == 0x00))
        {
            ih = (ip_header *) (packet+ 14);
            int numdatos_cabecera = ((*ih).ver_ihl & 0xf) * 4;
            if ((*ih).protocol == 0xFD)
            {
                u_char *datos = (u_char *)(packet + 14 + numdatos_cabecera);
                int sala_recibida = datos[0];

                if (sala_recibida == sala_usuario)
                {
                    char *mensaje = (char *)(datos + 1);
                    sip = &((*ih).saddr);
                    printf("%d.%d.%d.%d -> [%d] %s\n",
                        (*sip).byte1, (*sip).byte2, (*sip).byte3, (*sip).byte4,
                        sala_recibida, mensaje);
                }
            }
        }
    }

    if(res == -1)
    {
        printf("ERROR: %s\n", pcap_geterr(my_NIC_handle));
        return 5;
    }

    return 0;
}
