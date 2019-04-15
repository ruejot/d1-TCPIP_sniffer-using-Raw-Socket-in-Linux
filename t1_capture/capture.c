#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
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
int do_promisc(char *nif, int sock )
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
  if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1 )	
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



  char mac[16];
  int i,sock, r, len;

  char *data;
  char *ptemp;
  char ss[32],dd[32];
  long int total=0, ipnum=0, arpnum=0, rarpnum=0, tcpnum=0, udpnum=0, icmpnum=0, igmpnum=0, othernum=0;

  //raw socket
  if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
  {
    fail("socket");
  }

  do_promisc("eth0", sock);


  for(;;)
  {
    len = sizeof(addr);

    //receive packet
    r = recvfrom(sock, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&addr, (socklen_t*)&len);
    buf[r] = 0;
    ptemp = buf;
    peth = (struct ether_header *)ptemp;

    //count EtherType
    switch(ntohs(peth->ether_type))
    {
        case ETHERTYPE_IP:	  //ip:  ETHERTYPE_IP  0x0800
            ipnum++;
            break;
        case ETHERTYPE_ARP:	  //arp:  ETHERTYPE_ARP 0x0806
            arpnum++;
            break;
        case ETHERTYPE_REVARP:    //rarp:  ETHERTYPE_REVARP 0x8035
            rarpnum++;	
            break;
    }

    ptemp += sizeof(struct ether_header); //shift eth_head length, then point to ip header
    pip = (struct ip *)ptemp; //pip, point to ip layer header


    //count IPv4 header Protocol type 
    switch(pip->ip_p)
    {
        
        if(total>=100)
        break;

        case IPPROTO_TCP: //TCP
        tcpnum++;
        total++;
        break;

        case IPPROTO_UDP: //UDP
        udpnum++;
        total++;
        break;

        case  IPPROTO_ICMP: //ICMP
        icmpnum++;
        total++;
        break;

        case  IPPROTO_IGMP: //IGMP
        igmpnum++;
        total++;
        break;

        default:
        othernum++;
        total++;
        break;

    }

    if(total>=100)
    {
        printf("----statistics----------\n");	
        printf("\tIP \t:%ld\n",ipnum);
        printf("\tARP \t:%ld\n",arpnum);
        printf("\tRARP \t:%ld\n",rarpnum);
        printf("\tTCP \t:%ld\n",tcpnum);
        printf("\tUDP \t:%ld\n",udpnum);
        printf("\tICMP \t:%ld\n",icmpnum);
        printf("\tIGMP \t:%ld\n",igmpnum);
        printf("----finish----------\n");
        break;
    }

  }

}


