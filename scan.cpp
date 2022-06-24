/******************************
 * 2. projekt do predmetu IPK
 * 
 * Autor: Jakub Sadílek
 * Login: xsadil07
 * Dne: 21.4.2019
 * 
******************************/

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <regex>
#include <unistd.h>
#include <ifaddrs.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#define PORT 49224          // Port pres ktery programu komunikuje
#define PACKET_LEN 512
#define PACKET_COUNT 1
#define TIMEOUT_LIMIT 1000  // ms
#define FILTER_SIZE 100
#define ETHERNET_SIZE 14
#define REPEAT 2            // Max. pocet odeslanych paketu, pokud host neodpovi

/**
 * Struktura reprezentuje koncove zarizeni
*/
typedef struct {
    std::string addr = "";
    std::string interface = "";
} adr;

/**
 * Pomocna pseudo-hlavicka pro vypocet kontrolniho souctu tcp.
*/
struct pseudoTCPhdr {
  uint32_t srcAddr;
  uint32_t dstAddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t TCP_len;
};

std::vector<int> TCPports, UDPports;    // Seznamy portu
adr host, device;    // Struktury reprezentujici cleny komunikace
std::string output;  // Vysledny vypis programu
pcap_t *answer;      // Pro zachyceni paketu

/**
 * Funkce vypise zpravu na chybovy vystup a ukonci program.
 * @param msg Chybova hlaska.
 * @return 1
*/
void error(const char *msg){
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

/**
 * Funkce rozdeli porty v seznamu oddelenych carkou a vrati je ve vektoru.
 * @param ports Seznam portu.
 * @return Vektor interegu reprezentujici vstupni porty.
*/
std::vector<int> SplitPorts(char *ports){
    std::vector<int> result;
    std::string num = "";
    int len = strlen(ports);
    int port;

    for (int i = 0; i < len; i++){
        if (ports[i] == ','){
            port = std::stoi(num);
            if (1 > port || port > 65535)
                error("Port mimo povoleny rozsah.");

            result.push_back(port);
            num = "";
        }
        else
            num += ports[i];
    }
    port = std::stoi(num);
    if (1 > port || port > 65535)
        error("Port mimo povoleny rozsah.");

    result.push_back(port);
    return result;
}

/**
 * Funkce prevede seznam portu zadanych rozsahem na vektor integeru v tomto rozsahu.
 * @param ports Porty zadane rozsahem napr. 10-20.
 * @return Vektor portu v tomto rozsahu.
*/
std::vector<int> PortRange(char *ports){
    std::vector<int> result;
    std::string num = "";
    int len = strlen(ports);
    int begin, end;

    for (int i = 0; i < len; i++){
        if (ports[i] == '-'){
            begin = std::stoi(num);
            num = "";

            while (++i < len)
                num += ports[i];

            end = std::stoi(num);
        }
        else
            num += ports[i];
    }

    if (begin > end)
        error("Zadany rozsah neni vzestupny.");

    while (begin <= end){
        if (1 > begin || begin > 65535)
                error("Port mimo povoleny rozsah.");
        result.push_back(begin++);
    }
    return result;
}

/**
 * Funkce prevede zadane porty z agrumentu na vektor integeru.
 * @param result Pro ulozeni vysledneho vektoru.
 * @param argv Seznam portu zadanych z commandline.
*/
void ParsePorts(std::vector<int> &result, char *argv){
    if (std::regex_match(argv, std::regex("(\\d+(?:,\\d+)+)")))
        result = SplitPorts(argv);      // Porty oddelene ','
    else if (std::regex_match(argv, std::regex("(\\d+-\\d+)")))
        result = PortRange(argv);       // Rozsah portu '-'
    else if (std::regex_match(argv, std::regex("(\\d+)"))){
        int port = strtod(argv, NULL);  // Pouze jeden port byl zadany
        if (1 > port || port > 65535)
                error("Port mimo povoleny rozsah.");
        result.push_back(port);
    }
    else
        error("Spatne definovany seznam portu v argumentu programu.");
}

/**
 * Funkce prevede hostname na IPv4. 
 * @param hostname Jmeno domeny, ktere bude prevedeno.
 * @param ip Vysledek je vracen na tuto adresu.
 * @return Vraci 1 pri uspechu, jinak 0.
 * Inspirovano: https://stackoverflow.com/questions/5760302/when-i-do-getaddrinfo-for-localhost-i-dont-receive-127-0-0-1
*/
int Hostname2IP(char *hostname, std::string &ip){
    struct addrinfo *result, *tmp, hints;
    struct in_addr **AddrList;
    memset(&hints, 0, sizeof(struct addrinfo));
    char addrstr[100] = "";

    hints.ai_family = AF_INET;      // Vybereme IPv4 adresu
    hints.ai_socktype = SOCK_RAW;   // Preferenci pro RAW sokety
    hints.ai_protocol = 0;

    if ((getaddrinfo(hostname, NULL, &hints, &result)) != 0)
        return 0;

    for (tmp = result; tmp != NULL; tmp = tmp->ai_next){    // Projdeme adresy
        if (tmp->ai_family == AF_INET){                     // IPv4 adresa
            inet_ntop(AF_INET, &((struct sockaddr_in *)tmp->ai_addr)->sin_addr, addrstr, sizeof(addrstr));
            break;
        }
    }
    if (tmp == NULL){       // Nasli jsme?
        freeaddrinfo(result);
        error("Nenasla se IP adresa hosta.");
    }
    freeaddrinfo(result);   // Uvolnime pamet
    host.addr = addrstr;    // Ulozime adresu
    return 1;
}

/**
 * Funkce zkontroluje platnost domeny nebo IP.
 * @param addr Zadana IP adresa nebo nazev domeny.
*/
void ValidateIP(char *addr){
    struct sockaddr_in buf;

    if (inet_pton(AF_INET, addr, &buf) == 1){   // Primo zadana IP
        host.addr = addr;
    }
    else if (Hostname2IP(addr, host.addr)){     // Host zadany jmenem
        return;
    }
    else
        error("Spatna domena nebo IP adresa.");
}

/**
 * Funkce najde IPv4 adresu zarizeni podle nazadeho interfacu.
 * Pokud nenajde zadnou adresu ukonci program.
 * @param ifce Jmeno interfacu.
*/
void getIpInterface(char *iface){
    struct ifaddrs *interfaces, *tmp;

    if ((getifaddrs(&interfaces)) != 0)                 // Ziskame aktualni interfacy
        error("Chyba pri ziskavani interfacu.");
    
    for (tmp = interfaces; true; tmp = tmp->ifa_next){  // Projdeme interfacy
        if (tmp == NULL){
            freeifaddrs(interfaces);
            error("Nepodarilo se ziskat IP adresu z daneho interfacu.");
        }
        else if(strcmp(tmp->ifa_name, iface) == 0){     // Nasli jsme zadany interface
            if(tmp->ifa_addr->sa_family == AF_INET){    // IPv4 adresa
                device.addr = inet_ntoa(((struct sockaddr_in*)tmp->ifa_addr)->sin_addr);
                device.interface = tmp->ifa_name;       // Ulozime interface
                break;
            }
        }
    }
    freeifaddrs(interfaces);    // Uvolnime pamet
}

/**
 * Funkce najde a ulozi prvni neloopbackovou IP adresu IPv4.
 * Pokud ji nenajde ukonci program.
*/
void getFirstNonLoopbackIP(){
    struct ifaddrs *interfaces, *tmp;

    if ((getifaddrs(&interfaces)) != 0)             // Ziskame aktualni interfacy
        error("Chyba pri ziskavani interfacu.");
    
    for (tmp = interfaces; true; tmp = tmp->ifa_next){  // Projdeme interfacy
        if (tmp == NULL){
            freeifaddrs(interfaces);
            error("Nepodarilo se ziskat IP adresu");
        }
        else if(strcmp(tmp->ifa_name, "lo") != 0){  // Nasli jsme neloopbackovy interface
            if(tmp->ifa_addr->sa_family == AF_INET){    // IPv4 adresa
                device.addr = inet_ntoa(((struct sockaddr_in*)tmp->ifa_addr)->sin_addr);
                device.interface = tmp->ifa_name;
                break;
            }
        }
    }
    freeifaddrs(interfaces);    // Uvolnime pamet
}

/**
 * Funkce zkontroluje a zpracuje argumenty zadane programu.
*/
void ParseArgs(int argc, char **argv)
{
    if (argc > 8 || argc < 4)
        error("Spatny pocet argumentu.");

    bool pu, pt, ip, iface;     // Pomocne promenne pro zpracovani
    pt = pu = ip = iface = true;

    for(int i = 1; i < argc; i++){
        if (strcmp(argv[i], "-pt") == 0 && pt){       // TCP porty
            if (argc <= (i + 1))    // Kontrola rozsahu pole
                error("Nezadane porty.");
            ParsePorts(TCPports, argv[++i]);
            pt = false;
        }
        else if (strcmp(argv[i], "-pu") == 0 && pu){  // UDP porty
            if (argc <= (i + 1))    // Kontrola rozsahu pole
                error("Nezadane porty.");
            ParsePorts(UDPports, argv[++i]);
            pu = false;
        }
        else if (strcmp(argv[i], "-i") == 0 && iface){  // Interface
            if (argc <= (i + 1))    // Kontrola rozsahu pole
                error("Nezadany interface.");
            getIpInterface(argv[++i]);
            iface = false;
        }
        else if (ip){       // IP hosta
            ValidateIP(argv[i]);
            ip = false;
        }
        else
            error("Neznamy nebo prebytecny argument.");
    }
    if ((pt && pu) || ip)
        error("Nezadany povinny argument.");
    if (iface)  // Nezadan interface, berem prvni neloopbackovou ip
        getFirstNonLoopbackIP();
}

/**
 * Funkce vypocita kontrolni soucet paketu.
 * @param buf Paket pro vypocet.
 * @param nbytes delka paketu.
 * Inpirovano: https://stackoverflow.com/questions/8845178/c-programming-tcp-checksum
*/
unsigned short checkSum(unsigned short *buf, int nbytes){
    unsigned long sum = 0;

    while (nbytes > 1) {
      sum += *buf++;
      nbytes -= 2;      // sizeof(unsigned short)
    }

    if (nbytes) 
      sum += *(u_char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

/**
 * Funkce naplni IPv4 hlavicku.
 * @param header IP hlavicka pro naplneni.
 * @param protocol Pouzity protokol.
 * Inspirovano: https://www.tenouk.com/Module43a.html
*/
void fillIPheader(struct ip *header, const int protocol){
    header->ip_hl = 5;
    header->ip_v = 4;
    header->ip_tos = 0;
    header->ip_id = htons(54321);
    header->ip_off = 0;
    header->ip_ttl = 255;
    header->ip_p = protocol;
    header->ip_sum = 0;             // Prozatim 0
    header->ip_src.s_addr = inet_addr(device.addr.c_str());
    header->ip_dst.s_addr = inet_addr(host.addr.c_str());
    if (protocol == IPPROTO_TCP)
        header->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    else
        header->ip_len = sizeof(struct ip) + sizeof(struct udphdr);
}

/**
 * Funkce naplni TCP hlavicku.
 * @param header Odkaz na tcp halvicku pro naplneni.
*/
void fillTCPheader(struct tcphdr *header){
    header->source = htons(PORT);
    header->dest = 0;       // Zatim nenastavujeme
    header->seq = 0;        // Zatim nenastavujeme
    header->ack_seq = 0;
    header->res1 = 0;
    header->doff = 5;
    header->rst = 0;
    header->syn = 1;
    header->fin = 0;
    header->urg = 0;
    header->ack = 0;
    header->psh = 0;
    header->window = htons(65535); 
    header->check = 0;      // Zatim nenastavujeme
    header->urg_ptr = 0;
}

/**
 * Funkce naplni pseudoTCP hlavicku
 * @param header Odkaz na hlavicku pro naplneni.
*/
void fillPseudoTCPheader(struct pseudoTCPhdr *header){
    header->srcAddr = inet_addr(device.addr.c_str());
    header->dstAddr = inet_addr(host.addr.c_str());
    header->zero = 0;   // Vzdy 0
    header->protocol = IPPROTO_TCP;
    header->TCP_len = htons(sizeof(struct tcphdr));
}

/**
 * Funkce slouzi pro zpracovani odpovedi ze zachyceneho paketu.
 * Inspirovano: https://www.tcpdump.org/pcap.html
*/
void TCP_GotPacked(u_char *user, const struct pcap_pkthdr *header, const u_char *data){
    struct ip *IpHeader = (struct ip *)(data + ETHERNET_SIZE);  // Posun za ethernet hlavicku
    u_int IPsize = IpHeader->ip_hl * 4;
    struct tcphdr *TcpHeader = (struct tcphdr*)(data + ETHERNET_SIZE + IPsize);  // Posun za IP hlavicku

    if (TcpHeader->rst == 1)    // Obsahuje odpoved RST flag?
        output += "closed\n";
    else
        output += "open\n";
}

/**
 * Funkce slouzi pro ukonceni cekani na prichozi paket pokud neprisel do 2s. Vyuziva systemovy signal.
 * Inspirovano: https://stackoverflow.com/questions/4583386/listening-using-pcap-with-timeout
*/
void alarm_handler(int sig){
    pcap_breakloop(answer);
}

/**
 * Funkce provede TCP skenovani.
 * Vyzaduje zpracovane vstupni parametry.
*/
void TCPscan(){
    int sock, one = 1;
    struct sockaddr_in addr_in;             // Struktura adresy pro sendto()
    uint32_t initSeqGuess = 1138083240;     // Seq pro TCP hlavicku (nahodne zvolene)
    char packet[PACKET_LEN];                // Alokujeme velikost packetu
    memset(packet, 0, sizeof(packet));      // Vynulujeme

    addr_in.sin_family = AF_INET;           // IPv4
    addr_in.sin_addr.s_addr = inet_addr(host.addr.c_str());  // Adresa hosta

    struct ip *ipHeader = (struct ip *)packet;  // Na zacatek paketu vlozime IP hlavicku
    fillIPheader(ipHeader, IPPROTO_TCP);
    ipHeader->ip_sum = checkSum((unsigned short *)packet, ipHeader->ip_len);

    struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ip));   // Za IP vlozime TCP
    fillTCPheader(tcpHeader);

    /* Vytvorime pseudo-paket pomoci ktereho spocitame checksum pro TCP hlavicku.
        +----------------------------------------+
        |   pseudo-TCP header   |   TCP header   |   <--  Pseudo-paket 
        +----------------------------------------+
    */
    char pseudoPacket[(sizeof(struct pseudoTCPhdr) + sizeof(struct tcphdr))];   // Vytvorime pseudo paket
    memset(pseudoPacket, 0, sizeof(pseudoPacket));

    struct pseudoTCPhdr *tmpTCPhdr = (struct pseudoTCPhdr *)pseudoPacket;       // PseudoTCP hlavicka
    fillPseudoTCPheader(tmpTCPhdr);

    if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)  // Otevreme soket
        error("Chyba pri otvirani socketu.");

    // Nastaveni IP_HDRINCL (hlavicky jsou obsazeny v packetu)
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) == -1){
        close(sock);
        error("Chyba pri nastavovani socketu.");
    }

    for (unsigned i = 0; i < TCPports.size(); i++){  // Cyklime s kazdym portem
        output += std::to_string(TCPports[i]) + "/tcp\t";
        tcpHeader->dest = htons(TCPports[i]);   // Nastavime informace, ktere se meni s kazdym portem
        tcpHeader->seq = htonl(initSeqGuess++);
        addr_in.sin_port = htons(TCPports[i]);
        tcpHeader->th_sum = 0;
        memcpy(pseudoPacket + sizeof(struct pseudoTCPhdr), tcpHeader, sizeof(tcphdr));  // Vlozime TCP hlavicku za pseudoTCP

        tcpHeader->th_sum = checkSum((unsigned short *)&pseudoPacket, sizeof(struct pseudoTCPhdr) + sizeof(struct tcphdr));

        /**** Odpoved ****/
        char errbuf[PCAP_ERRBUF_SIZE];  // Error string
        struct bpf_program fp;          // Zkompilovany filtr

        if ((answer = pcap_open_live(device.interface.c_str(), BUFSIZ, PACKET_COUNT, TIMEOUT_LIMIT, errbuf)) == NULL){
            close(sock);
            error("Nastala chyba pri zachytavani packetu.");
        }

        char filter[FILTER_SIZE];           // Budeme filtrovat pakety pouze na ten co nas zajima
        memset(filter, 0, FILTER_SIZE);     // Nastavime TCP, src a dst zarizeni a dst port
        sprintf(filter, "tcp and src host %s and dst host %s and dst port %d", host.addr.c_str(), device.addr.c_str(), PORT);

        bpf_u_int32 net;
        if ((pcap_compile(answer, &fp, filter, 0, net)) == -1){  // Zkonpilujeme filtr
            close(sock);
            error("Chyba pri parsovani filtru.");
        }
        if (pcap_setfilter(answer, &fp) == -1){     // Nainstalujeme filtr
            close(sock);
            pcap_freecode(&fp);
            error("Chyba pri aplikovani filtru.");
	    }

        for (int j = 0; j < REPEAT; j++){   // Pokud nedojde odpoved posleme paket jeste jednou.
            if ((sendto(sock, packet, ipHeader->ip_len, 0, (struct sockaddr *)&addr_in, sizeof(addr_in))) == -1){
                close(sock);
                error("Chyba pri odeslani packetu");
            }

            alarm(2);       // Timeout
            signal(SIGALRM, alarm_handler);
            int ret;        // Chytnem odpoved
            if ((ret = pcap_dispatch(answer, PACKET_COUNT, TCP_GotPacked, NULL)) < 0){
                if (j == (REPEAT - 1))
                    output += "filtrated\n";
                else
                    continue;
            }
            else
                break;
        }

        pcap_freecode(&fp);
        pcap_close(answer);
    }
    close(sock);
}

/**
 * Funkce naplni UDP hlavicku.
 * @param header UDP hlavicka pro naplneni
*/
void fillUDPheader(struct udphdr *header){
    header->source = htons(PORT);
    header->len = htons(sizeof(struct udphdr));
    header->check = 0;
}

/**
 * Funkce pro zpracovani odpovedi. Velmi podobne TCP skenovani.
*/
void UDP_GotPacked(u_char *user, const struct pcap_pkthdr *header, const u_char *data){
    struct ip *IpHeader = (struct ip *)(data + ETHERNET_SIZE);  // Posun za ethernet hlavicku
    u_int IPsize = IpHeader->ip_hl * 4;
    struct icmp *IcmpHeader = (struct icmp*)(data + ETHERNET_SIZE + IPsize);    // Posun za IP hlavicku

    if (IcmpHeader->icmp_type == 3)     // ICMP typu 3 = closed.
        output += "closed\n";
    else
        output += "open\n";
}

/**
 * Funkce provede UDP skenovani. Velmi podobne TCP skenovani.
 * Vyzaduje zpracovane vstupni parametry.
*/
void UDPscan(){
    int sock, one = 1;
    struct sockaddr_in addr_in;             // Struktura adresy pro sendto()
    char packet[PACKET_LEN];                // Alokujeme velikost packetu
    memset(packet, 0, sizeof(packet));      // Vynulujeme

    addr_in.sin_family = AF_INET;           // IPv4
    addr_in.sin_addr.s_addr = inet_addr(host.addr.c_str());     // Adresa hosta

    struct ip *ipHeader = (struct ip *)packet;  // Vlozime na zacatek IP hlavicku a naplnime
    fillIPheader(ipHeader, IPPROTO_UDP);
    ipHeader->ip_sum = checkSum((unsigned short *)packet, ipHeader->ip_len);

    struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ip));   // Za IP vlozime UDP hlavicku
    fillUDPheader(udpHeader);

    if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)  // Otevreme soket s UDP protokolem
        error("Chyba pri otvirani socketu.");

    // Nastaveni IP_HDRINCL (hlavicky jsou obsazeny v packetu)
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) == -1){
        close(sock);
        error("Chyba pri nastavovani socketu.");
    }

    for (unsigned i = 0; i < UDPports.size(); i++){     // S kazdym UDP portem
        output += std::to_string(UDPports[i]) + "/udp\t";
        addr_in.sin_port = htons(UDPports[i]);
        udpHeader->dest = htons(UDPports[i]);

        /**** Odpoved ****/
        char errbuf[PCAP_ERRBUF_SIZE];  // Error string
        struct bpf_program fp;          // Zkompilovany filtr

        if ((answer = pcap_open_live(device.interface.c_str(), BUFSIZ, PACKET_COUNT, 1000, errbuf)) == NULL){
            close(sock);
            error("Nastala chyba pri zachytavani packetu.");
        }

        char filter[FILTER_SIZE];       // Filtr nastavime na ICMP, src a dst zarizeni
        memset(filter, 0, FILTER_SIZE);
        sprintf(filter, "icmp and src host %s and dst host %s", host.addr.c_str(), device.addr.c_str());

        bpf_u_int32 net;                // Zkompilujeme filtr
        if ((pcap_compile(answer, &fp, filter, 0, net)) == -1){
            close(sock);
            error("Chyba pri parsovani filtru.");
        }
        if (pcap_setfilter(answer, &fp) == -1){     // Nainstalujeme filtr
            close(sock);
            pcap_freecode(&fp);
            error("Chyba pri aplikovani filtru.");
	    }

        for (int j = 0; j < REPEAT; j++){   // Pokud nedosta odpoved posleme dalsi paket
            if ((sendto(sock, packet, ipHeader->ip_len, 0, (struct sockaddr *)&addr_in, sizeof(addr_in))) == -1){
                close(sock);
                error("Chyba pri odeslani packetu");
            }

            alarm(2);       // Timeout
            signal(SIGALRM, alarm_handler);
            int ret;        // Zachytneme odpoved
            if ((ret = pcap_dispatch(answer, PACKET_COUNT, UDP_GotPacked, NULL)) <= 0){
                if (j == (REPEAT - 1))
                    output += "open\n";
                else
                    continue;
            }
            else
                break;
        }
        pcap_freecode(&fp);
        pcap_close(answer);
    }
    close(sock);
}

int main(int argc, char **argv){
    ParseArgs(argc, argv);  // Zpracujeme argumenty
    output = "Interesting ports on " + host.addr + ":\n" + "PORT\tSTATE\n";

    if (!TCPports.empty())  // Provedeme sken nad TCP porty
        TCPscan();
    if (!UDPports.empty())  // Sken nad UDP porty
        UDPscan();

    printf("%s", output.c_str());   // Vypis vysledku
    return 0;
}
