/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include"thread.h"
#include "pcap.h"
#include"packetmanager.h"
#include <time.h>

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

void loadFile();
bool filteringSite(char* data);

pcap_t *adhandle;
u_int8_t myMacAddress[8];
u_int8_t myIpv4Address[6];
u_int8_t macBroadCast[8]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,};
bool    stop=false;

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];

    //file read
    loadFile();

    /* Retrieve the device list */
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);

    /* Check if the user specified a valid adapter */
    if(inum < 1 || inum > i)
    {
        printf("\nAdapter number out of range.\n");

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);


    if(d->addresses==NULL)
    {
        printf("wrong network");
        return -1;
    }
    memcpy(myIpv4Address,d->addresses->next->addr->sa_data+2,4);
    printf("My : %d.%d.%d.%d\n",myIpv4Address[0],myIpv4Address[1],myIpv4Address[2],myIpv4Address[3]);


    /* Open the adapter */
    if ((adhandle= pcap_open_live(d->name,	// name of the device
                             65536,			// portion of the packet to capture.
                                            // 65536 grants that the whole packet will be captured on all the MACs.
                             1,				// promiscuous mode (nonzero means promiscuous)
                             1000,			// read timeout
                             errbuf			// error buffer
                             )) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. is not supported by WinPcap\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }



    /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    pcap_loop(adhandle, 0, packet_handler, NULL);


    /* At this point, we don't need any more the device list. Free it */
    //pcap_freealldevs(alldevs);
    return 0;
}



/* Packet Manager Test*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    /*
     * unused parameter
     */
    (void)(param);

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* print timestamp and length of the packet */
    printf("%s.%.6d len:%d \n", timestr, header->ts.tv_usec, header->len);


    char type[25];
    EthernetManager*    oldRoot        =new EthernetManager((u_int8_t*)pkt_data,header->len);
    IPManager*          oldIPManager;
    TCPManager*         oldTCPManager;
    StringManager*      oldStringManager;
    u_int8_t oldData[1700];

    EthernetManager*    newRoot;
    IPManager*          newIPManager;
    TCPManager*         newTCPManager;
    StringManager*      newStringManager;
    u_int8_t newData[1700];
    u_int8_t sAddr[16];
    u_int8_t dAddr[16];

    oldRoot->getSubProtocolManager()->getProtocolTypeAsString(type,25);
    if(strcmp(type,"IP")==0)
    {
        oldIPManager=(IPManager*)oldRoot->getSubProtocolManager();
        oldIPManager->getSubProtocolManager()->getProtocolTypeAsString(type,25);
        if(strcmp(type,"TCP")==0)
        {
            oldTCPManager=(TCPManager*)oldIPManager->getSubProtocolManager();
            oldStringManager=(StringManager*)oldTCPManager->getSubProtocolManager();

            oldStringManager->getRawStream(oldData,1700);
            oldData[oldStringManager->getRawStreamLength()]=0;
            if(strstr((char*)oldData,"GET") && filteringSite(strstr((char*)oldData,"GET")))
            {
                char responce[]="HTTP/1.1 302 Found\nLocation: http://www.daum.net/";
                newStringManager=new StringManager((u_int8_t*)responce,sizeof(responce));
                {
                    oldTCPManager->getDestinationAddress(dAddr,16);
                    oldTCPManager->getSourceAddress(sAddr,16);
                    newTCPManager =new TCPManager(ntohs(*(u_int16_t*)dAddr),ntohs(*(u_int16_t*)sAddr),
                                                  oldTCPManager->getAckNumber(),oldTCPManager->getSeqNumber(),
                                                  TH_ACK|TH_FIN,newStringManager);
                    printf("oldTCP\nACK: %u\nSEQ: %u\n",(oldTCPManager->getAckNumber()),(oldTCPManager->getSeqNumber()));
                    printf("newTCP\nACK: %u\nSEQ: %u\n",(newTCPManager->getAckNumber()),(newTCPManager->getSeqNumber()));
                    {
                        oldIPManager->getDestinationAddress(dAddr,16);
                        oldIPManager->getSourceAddress(sAddr,16);
                        newIPManager=new IPManager(4,dAddr,sAddr,newTCPManager);
                        newIPManager->setID(rand());
                        {
                            oldRoot->getDestinationAddress(dAddr,16);
                            oldRoot->getSourceAddress(sAddr,16);
                            newRoot=new EthernetManager(dAddr,sAddr,newIPManager);

                            newRoot->getRawStream(newData,1700);

                            printf("ip ID : %d",ntohs(newIPManager->getID()));
                            if(pcap_sendpacket(adhandle,newData,newRoot->getRawStreamLength()))
                            {
                                fprintf(stderr,"target to gate error\n");
                            }
                            delete newRoot;
                        }
                        delete newIPManager;
                    }
                    delete newTCPManager;
                }
                delete newStringManager;
            }
        }
    }
    printf("\n");

}

struct SiteList
{
    char* protocol;
    char* domain;
    char* path;
    SiteList* next;
};

SiteList siteListHead;

void loadFile()
{
    FILE* fp;

    fopen_s(&fp,"mal_site.txt","r");
    if(fp==0)
    {
        printf("file does not exist.\n");
        return;
    }
    char url[1024];
    char* head,*tail;
    SiteList* last=&siteListHead;
    while(fscanf(fp,"%[^\n]\n",url)!=EOF)
    {
        head=url;
        tail=strstr(url,"://");
        last->protocol=new char[(tail-head)+1];
        memcpy(last->protocol,head,(tail-head));
        last->protocol[(tail-head)]=0;

        head=tail+3;
        tail=strstr(head,"/");
        if(tail==0)
            tail=head+strlen(head);
        last->domain=new char[(tail-head)+1];
        memcpy(last->domain,head,(tail-head));
        last->domain[(tail-head)]=0;


        head=tail;
        tail=head+strlen(head);
        last->path=new char[(tail-head)+1];
        memcpy(last->path,head,(tail-head));
        last->path[(tail-head)]=0;

        last->next=new SiteList;
        last=last->next;
        memset(last,0,sizeof(SiteList));
    }
    fclose(fp);
}

bool filteringSite(char* data)
{
    SiteList*site;
    char    *domain;
    char    *path;
    site=&siteListHead;
    bool    found=false;
    while(site && site->domain)
    {
        domain=strstr(data,site->domain);
        path=strstr(data,site->path);
        if(domain && path)
        {
            found=true;
            while(domain)
            {
                memset(domain,'a',strlen(site->domain));
                fprintf(stderr,"replaced : %s\n",site->domain);
                domain=strstr(domain,site->domain);
            }
        }
        site=site->next;
    }
    return found;
}
