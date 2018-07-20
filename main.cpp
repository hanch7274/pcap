#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  int dst_mac_std = 0;
  int src_mac_std = 6;
  int src_ip_std = 26;
  int dst_ip_std = 30;
  int src_port_std = 34;
  int dst_port_std = 36;
  int payload_std = 54;
  char* dev = argv[1];

	
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); //dev_name, buffer,promiscuous mode,rtimeout,error_buf
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
	//print(src_mac)
	printf("src mac_addr : ");
	printf("%02x",*(packet+src_mac_std));	
	for(int i=1;i<6;i++)
	{
		printf(":%02x",*(packet+src_mac_std+i));
		if(i==5)printf("\n");
	}
	//print(dst_mac)
	printf("dst mac_addr : ");
	printf("%02x",*packet);	
	for(int i=1;i<6;i++)
	{
		printf(":%02x",*(packet+i));
		if(i==5)printf("\n");
	}
    //print(src_ip)
	printf("src ip_addr : ");
	printf("%d",*(packet+src_ip_std));	
	for(int i=1;i<4;i++)
	{
		printf(".%d",*(packet+src_ip_std+i));
		if(i==3)printf("\n");
	}
	//print(dst_ip)
	printf("dst ip_addr : ");
	printf("%d",*(packet+dst_ip_std));	
	for(int i=1;i<4;i++)
	{
		printf(".%d",*(packet+dst_ip_std+i));
		if(i==3)printf("\n");
	}
	//print(src_port)
	int src_port[3];
	src_port[0] = (int)*(packet+src_port_std);
	src_port[1] = (int)*(packet+src_port_std+1);
	printf("src port : ");
	printf("%d\n", (src_port[0]<<8)+src_port[1]);
	//print(dst_port)
	int dst_port[5];
	dst_port[0] = (int)*(packet+dst_port_std);
	dst_port[1] = (int)*(packet+dst_port_std+1);	
	printf("dst port : ");
	printf("%d\n", (dst_port[0]<<8)+dst_port[1]);
	//print(data)
	char data[17];
	printf("data\n=>%s", memcpy(data,(packet+payload_std),16));
	printf("\n----------------------------------------------");
    if (res == 0) continue;//timeout
    if (res == -1 || res == -2) break; // error
    printf("%u bytes captured\n", header->caplen);
  }
	
  pcap_close(handle);
  return 0;
}
