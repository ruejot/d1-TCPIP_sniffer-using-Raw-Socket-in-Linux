#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>

//error report
void fail(char *incident)
{
  perror(incident);
  exit(1);         
}

//set network interface to promiscuous mode
int do_promisc(char *nif, int sock)
{
  struct ifreq ifr;
  strncpy(ifr.ifr_name, nif, strlen(nif) + 1);
  //get
  if ((ioctl(sock, SIOCGIFFLAGS, &ifr) == -1))
  {
    fail("ioctl");
  }
  //change to promiscuous
  ifr.ifr_flags |= IFF_PROMISC;
  //set
  if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1)
  {
    fail("ioctl");
  }
}

char buf[40960];

int main(int argc, char *argv[])
{
  struct sockaddr_in addr;
  struct ether_header *peth;
  struct ip *pip;
  struct tcphdr *ptcp;
  struct udphdr *pudp;

  unsigned char *mac_s, *mac_d;
  int i, sock, r, len;
  char *data;
  char *ptemp;
  char ss[32], dd[32];
  long int total = 0, ipnum = 0, arpnum = 0, rarpnum = 0, tcpnum = 0, udpnum = 0, icmpnum = 0, igmpnum = 0, othernum = 0;

  //raw socket
  if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
  {
    fail("socket");
  }

  do_promisc("eth0", sock);

  
  for (;;)
  {
    len = sizeof(addr);
    //receive packet
    r = recvfrom(sock, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&addr, (socklen_t*)&len);
    buf[r] = 0;
    ptemp = buf;
    peth = (struct ether_header *)ptemp;

    ptemp += sizeof(struct ether_header); //shift eth_head length, then point to ip header
    pip = (struct ip *)ptemp;          //pip, point to ip header

    ptemp += sizeof(struct ip); //shift ip header length, then point to next layer header(UDP)

    //count udp
    switch (pip->ip_p)
    {
      if (udpnum >= 10)
      {
        break;
      }
    case IPPROTO_UDP:
      pudp = (struct udphdr *)ptemp; //shift pointer(pudp) to udp header

      mac_s = peth->ether_shost; //s: source mac
      mac_d = peth->ether_dhost; //d: destination mac


      char s_macaddr[18];
      char d_macaddr[18];
      //convert Hex to string
      sprintf(s_macaddr, "%x:%x:%x:%x:%x:%x", mac_s[0], mac_s[1], mac_s[2], mac_s[3], mac_s[4], mac_s[5]);
      
      sprintf(d_macaddr, "%x:%x:%x:%x:%x:%x", mac_d[0], mac_d[1], mac_d[2], mac_d[3], mac_d[4], mac_d[5]);
      
      char mymacaddr[] = /**.....**/; //record the host MAC address of mine
      
      //rule out source and destination are the same
      if (strcmp(s_macaddr, mymacaddr) != 0 && strcmp(d_macaddr, mymacaddr) != 0 && strcmp(d_macaddr, s_macaddr) != 0)
      {
	
        printf("----------- UDP packets %ld --------------------------\n", udpnum + 1);

        printf("Source MAC address:      %s\n", s_macaddr);
        printf("Destination MAC address: %s\n", d_macaddr);

        printf("IP->protocol=UDP\n");
        printf("IP->src_ip =%s \n", inet_ntoa(*(struct in_addr *)&(pip->ip_src)) );
        printf("IP->dst_ip =%s \n", inet_ntoa(*(struct in_addr *)&(pip->ip_dst)) );
        udpnum++;
      }
      break;
    }

    if (udpnum >= 10)
    {
      printf("-----------------------------------------------------\n");
      break;
    }
  }
}
