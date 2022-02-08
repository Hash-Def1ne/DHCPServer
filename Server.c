#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define SERVER_PORT 67
#define CLIENT_PORT 68
#define BUFF_SIZE 350

socklen_t addr_len;

struct sockaddr_in addr;
struct sockaddr_in client_addr;

unsigned char buf[BUFF_SIZE] = {0};
unsigned char ip = 2;
//unsigned char atksendbuf[BUFF_SIZE] = {0x02,0x01,0x06,0x00,0x60,0xb1,0x24,0x50,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xa8,0xe9,0x02,0xc0,0xa8,0xe9,0x01,0x00,0x00,0x00,0x00,0x40,0x8d,0x5c,0xb1,0x24,0x50,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x43,0x6f,0x6e,0x66,0x69,0x67,0x75,0x72,0x65,0x2e,0x69,0x6e,0x69,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x63,0x82,0x53,0x63,0x35,0x01,0x05,0x01,0x04,0xff,0xff,0xff,0x00,0x03,0x04,0x00,0x00,0x00,0x00,0x06,0x04,0x0a,0x00,0x00,0x01,0x1c,0x04,0xc0,0xa8,0xe9,0xff,0x33,0x04,0x00,0x00,0x0e,0x10,0x36,0x04,0xc0,0xa8,0xe9,0x01,0xff};

int deBug = 0;

int Help(){
    printf("usage:\n");
    printf("    -d    Set debug level. Default:0\n");
    printf("    -s    Bind IP address. Default:0.0.0.0\n");
    printf("    -sp   Set server port. Default:67\n");
    printf("    -cp   Set client port. Default:68\n");
    printf("    -D   Set dhcp address. Default:192.168.1.1\n");
    printf("    -bf   Set bootfile name. Default:pxelinux.0\n");

    exit(0);
}

int InitDHCPData(){
    //char tempAddress[32] = {buf[4],buf[5],buf[6],buf[7],buf[28],buf[29],buf[30],buf[31],buf[32],buf[33],buf[242]};  //0-3 XID | 4-9 MAC address | 10 DHCP flag | 11 Subnet address

    //memset(buf,0,BUFF_SIZE);

    //buf[4] = tempAddress[0],buf[5] = tempAddress[1],buf[6] = tempAddress[2],buf[7] = tempAddress[3]; //XID
    //buf[28] = tempAddress[4],buf[29] = tempAddress[5],buf[30] = tempAddress[6],buf[31] = tempAddress[7],buf[32] = tempAddress[8],buf[33] = tempAddress[9]; //MAC address
    //buf[242] = tempAddress[10]; //DHCP flag*/



    //initinalization DHCP Data.
    buf[0] = 0x02,buf[1] = 0x01,buf[2] = 0x06,buf[3] = 0x00; //OP HTYPE HLEN HOPS

    //buf[4] = 0x39,buf[5] = 0x03,buf[6] = 0xf3,buf[7] = 0x26; //XID

    //buf[8] = 0x00,buf[9] = 0x00; //SECS
    //buf[10] = 0x00,buf[11] = 0x00; //FLAGS

    buf[12] = 0x00,buf[13] = 0x00,buf[14] = 0x00,buf[15] = 0x00; //CIADDR
    buf[16] = 0xc0,buf[17] = 0xa8,buf[18] = 0xe9,buf[19] = 0x02; //YIADDR
    buf[19] = ip;
    buf[20] = 0xc0,buf[21] = 0xa8,buf[22] = 0xe9,buf[23] = 0x01; //SIADDR
    buf[24] = 0x00,buf[25] = 0x00,buf[26] = 0x00,buf[27] = 0x00; //GIADDR


    buf[108] = 0x54,buf[109] = 0x65,buf[110] = 0x73,buf[111] = 0x74; //PXE FileName
    buf[236] = 0x63,buf[237] = 0x82,buf[238] = 0x53,buf[239] = 0x63; //Magic cookie

    if(buf[242] == 0x01) buf[240] = 0x35,buf[241] = 0x01,buf[242] = 0x02; //DHCP message type 53:2(Offer)
    if(buf[242] == 0x03) buf[240] = 0x35,buf[241] = 0x01,buf[242] = 0x05; //DHCP message type 53:5(ACK)

    for(int x = 243;x < BUFF_SIZE;x++) buf[x] = 0x00;

    buf[243] = 0x01,buf[244] = 0x04,buf[245] = 0xff,buf[246] = 0xff,buf[247] = 0xff,buf[248] = 0x00; //Subnet mask
    //buf[249] = 0x03,buf[250] = 0x04,buf[251] = 0xc0,buf[252] = 0xa8,buf[253] = 0xe9,buf[254] = 0x01; //Router address
    //buf[255] = 0x06,buf[256] = 0x04,buf[257] = 0x0a,buf[258] = 0x00,buf[259] = 0x00,buf[260] = 0x01; //Dimain name server option
    //buf[261] = 0x1c,buf[262] = 0x04,buf[263] = 0xc0,buf[264] = 0xa8,buf[265] = 0xe9,buf[266] = 0xff; //BroadCast address
    buf[267] = 0x33,buf[268] = 0x04,buf[269] = 0x00,buf[270] = 0x00,buf[271] = 0x0e,buf[272] = 0x10; //IP address lease time
    buf[273] = 0x36,buf[274] = 0x04,buf[275] = 0xc0,buf[276] = 0xa8,buf[277] = 0xe9,buf[278] = 0x01; //DHCP server

    buf[279] = 0xff; //End

}

int Print(int type){
    if(type == 0){
        printf("Get Data:\n");
        if(buf[242] == 0x01) printf("----DISCOVERY----\n");
        if(buf[242] == 0x03) printf("-----REQUEST-----\n");
    }
    if(type == 1){
        printf("Send Data:\n");
        if(buf[242] == 0x02) printf("------OFFER------\n");
        if(buf[242] == 0x05) printf("-------ACK-------\n"),ip++;
    }

    printf("Mac:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",buf[28],buf[29],buf[30],buf[31],buf[32],buf[33]);

    if(deBug >= 1){
        printf("Client address:%d.%d.%d.%d\n",buf[16],buf[17],buf[18],buf[19]);
        printf("Subnet mask:%d.%d.%d.%d\n",buf[245],buf[246],buf[247],buf[248]);
        printf("Router address:%d.%d.%d.%d\n",buf[251],buf[252],buf[253],buf[254]);
        printf("Broadcast address:%d.%d.%d.%d\n",buf[263],buf[264],buf[265],buf[266]);
    }
    if(deBug >= 2){
    }
    if(deBug >= 3){
        printf("Raw Hex:");
        for(int x = 0;x < BUFF_SIZE;x++){
            printf("%.2x",buf[x]);
        }
        printf("\n");
    }
    printf("\n");
}

int Bind(int fd,struct sockaddr_in addr,int port){
    addr.sin_port = htons(port);
    addr_len  = sizeof(addr);
    if(bind(fd,(struct sockaddr*)&addr,sizeof(addr)) < 0){
        printf("Bind Failed!\n");
        exit(1);
    };
    return 0;
}

int BOOTPServer(){
    int bootpsock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);

    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(CLIENT_PORT);
    client_addr.sin_addr.s_addr = INADDR_BROADCAST;
    addr.sin_family = AF_INET;

    Bind(bootpsock,addr,SERVER_PORT);
    
    while(1){
        recv(bootpsock,&buf,BUFF_SIZE,0);
        Print(0);

        InitDHCPData();
        sendto(bootpsock,buf,BUFF_SIZE,0,(struct sockaddr*)&client_addr,sizeof(client_addr));
        Print(1);

    }
}

unsigned long CharToDec(char *inChar){
    unsigned long outDec;
    for(unsigned long count = 1,nums = 0;nums <= strlen(inChar) - 1;count *= 10,nums++){
        if(inChar[nums] >= 48 && inChar[nums] <= 57){
            if(count == 1) outDec = inChar[nums] - 48;
            if(count > 1){
                if(inChar[nums] - 48 == 0) outDec *= 10;
                else outDec = outDec * 10 + inChar[nums] - 48;
            }
        }else{
            printf("Error!\n");
            exit(1);
        }
    }
    return outDec;
}

int Checkargc(int args, char **argc){
    int index = 1;

    addr.sin_addr.s_addr = inet_addr("0.0.0.0");

    for(int num = 0;num < args;num++) printf("args:%d,argc:%s\n",args,argc[num]);
    if(args > 1){
        printf("args:%d\n",args);
        while(1){
            if(index < args){
                if(index < args && strcmp(argc[index],"-d") == 0)
                    if(CharToDec(argc[index + 1]) >= 0 && CharToDec(argc[index + 1]) <= 3) deBug = CharToDec(argc[index + 1]),index+=2;
                    else printf("Input Range Error!\n"),exit(1);
                printf("%d\n",index);
                if(index < args && strcmp(argc[index],"-s") == 0) addr.sin_addr.s_addr = inet_addr(argc[index + 1]),index+=2;
                printf("%d\n",index);
                if(index < args && strcmp(argc[index],"-h") == 0) Help(),index+=2;
            }else break;
        }
            
    }
    printf("Debug level:%d\n",deBug);
}

int main(int args,char **argc){
    printf("Hash's DHCP for Netboot. Beta 0.0.1\n");
    Checkargc(args,argc);
    printf("Server Started.\n");
    BOOTPServer();
}

/*Hash_Define*/