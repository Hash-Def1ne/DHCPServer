#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

#define BUFF_SIZE 500
#define infoLen 9

socklen_t addr_len;

struct sockaddr_in server_addr;
struct sockaddr_in client_addr;
struct ifreq interface;

unsigned char buf[BUFF_SIZE] = {0},bufCache[BUFF_SIZE] = {0},ip = 2,*SERVER_ADDR = "0.0.0.0";
char *interfaceName = "";

int SERVER_PORT = 67,CLIENT_PORT = 68;
int deBug = 0,bootFileNameChanged = 0,dhcpAddressChanged = 0,interfaceChanged = 0;

int Help(){
    printf("usage:\n");
    printf("    -d    Set debug level. Default:0\n");
    printf("    -s    Bind IP address. Default:0.0.0.0\n");
    printf("    -sp   Set server port. Default:67\n");
    printf("    -cp   Set client port. Default:68\n");
    printf("    -D    Set dhcp address. Default:192.168.1.1\n");
    printf("    -bf   Set bootfile name. Default:pxelinux.0\n");
    printf("    -i    Bind interface.\n");
    exit(0);
}

int Writebootfilename(unsigned char *inChar){
    unsigned int inCharLen = strlen(inChar),count = 0,bufCount = 108;
    if(inCharLen <= 127){
        for(;count < inCharLen;count++,bufCount++) bufCache[bufCount] = inChar[count];
    }else{
        printf("Filename too long.\n");
        exit(1);
    }
    bootFileNameChanged = 1;
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

int CharToAddress(){
    return 0;
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

int Cacherestore(int start,int end){
    for(;start <= end;start++) buf[start] = bufCache[start];
}

int Cleararr(int start,int end){
    for(;start <= end;start++) buf[start] = 0x00;
}

int isPXEClient(){
    int count = 0,bufCount = 315,returnCode = 0;
    unsigned char PXEClientASCII[infoLen] = "PXEClient";
    for(;count < infoLen;count++,bufCount++){
        if(buf[bufCount] != PXEClientASCII[count]) returnCode++;
    }
    //return returnCode;
    return 0;
}

int InitDHCPData(){
    /*char tempAddress[32] = {buf[4],buf[5],buf[6],buf[7],buf[28],buf[29],buf[30],buf[31],buf[32],buf[33],buf[242]};  //0-3 XID | 4-9 MAC address | 10 DHCP flag | 11 Subnet address

    memset(buf,0,BUFF_SIZE);

    buf[4] = tempAddress[0],buf[5] = tempAddress[1],buf[6] = tempAddress[2],buf[7] = tempAddress[3]; //XID
    buf[28] = tempAddress[4],buf[29] = tempAddress[5],buf[30] = tempAddress[6],buf[31] = tempAddress[7],buf[32] = tempAddress[8],buf[33] = tempAddress[9]; //MAC address
    buf[242] = tempAddress[10]; //DHCP flag*/



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


    if(bootFileNameChanged == 0) buf[108] = 0x70,buf[109] = 0x78,buf[110] = 0x65,buf[111] = 0x6c,buf[112] = 0x69,buf[113] = 0x6e,buf[114] = 0x75,buf[115] = 0x78,buf[116] = 0x2e,buf[117] = 0x30; //PXE FileName
    else Cacherestore(108,234);

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

    for(int x = 0;x < BUFF_SIZE;x++){
        bufCache[x] = buf[x];
    }
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
        printf("Raw Hex:");
        for(int x = 0;x < BUFF_SIZE;x++){
            printf("%.2x",buf[x]);
            //printf("%c",buf[x]);
        }
        printf("\n");
    }
    printf("\n");
}

int BOOTPServer(){
    int bootpsock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    int allow = 1;

    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(CLIENT_PORT);
    client_addr.sin_addr.s_addr = INADDR_BROADCAST;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);
    strcpy(interface.ifr_name,interfaceName);

    setsockopt(bootpsock,SOL_SOCKET,SO_BROADCAST,&allow,sizeof(allow));
    if(interfaceChanged = 1 && setsockopt(bootpsock,SOL_SOCKET,SO_BINDTODEVICE,(char*)&interface,sizeof(interface)) != 0) printf("Bind interface failed.\n"),exit(1);

    Bind(bootpsock,server_addr,SERVER_PORT);

    printf("Server Started.\n");

    while(1){
        recv(bootpsock,&buf,BUFF_SIZE,0);
        if(deBug >= 3){
            printf("Raw Hex:");
            for(int x = 0;x < BUFF_SIZE;x++){
                printf("%.2x",buf[x]);
                //printf("%c",buf[x]);
            }
            printf("\n");
        }
        //for(;;) sendto(bootpsock,buf,BUFF_SIZE,0,(struct sockaddr*)&client_addr,sizeof(client_addr));
        if(isPXEClient() == 0 || buf[242] == 0x03 && buf[245] == bufCache[16] && buf[246] == bufCache[17] && buf[247] == bufCache[18] && buf[248] == bufCache[19]){
            Print(0);
            InitDHCPData();
            sendto(bootpsock,buf,BUFF_SIZE,0,(struct sockaddr*)&client_addr,sizeof(client_addr));
            Print(1);
        }else printf("Not PXE client data,Dropped.\n");
    }
}

int Checkargc(int args, char **argc){
    int index = 1;

    //for(int num = 0;num < args;num++) printf("args:%d,argc:%s\n",args,argc[num]);
    if(args > 1){
        while(1){
            if(index < args){
                if(index < args && strcmp(argc[index],"-d") == 0)
                    if(CharToDec(argc[index + 1]) >= 0 && CharToDec(argc[index + 1]) <= 3) deBug = CharToDec(argc[index + 1]),index+=2;
                    else printf("Input Range Error!\n"),exit(1);
                if(index < args && strcmp(argc[index],"-s") == 0) SERVER_ADDR = argc[index + 1],index+=2;
                if(index < args && strcmp(argc[index],"-bf") == 0) Writebootfilename(argc[index + 1]),index+=2;
                if(index < args && strcmp(argc[index],"-cp") == 0) CLIENT_PORT = CharToDec(argc[index + 1]),index+=2;
                if(index < args && strcmp(argc[index],"-sp") == 0) SERVER_PORT = CharToDec(argc[index + 1]),index+=2;
                if(index < args && strcmp(argc[index],"-i") == 0) interfaceName = argc[index + 1],interfaceChanged = 1,index+=2;
                if(index < args && strcmp(argc[index],"-h") == 0) Help(),index+=2;
            }else break;
        }
    }
    printf("Debug level:%d\nServer Prot:%d\n",deBug,SERVER_PORT);
}

int main(int args,char **argc){
    printf("Hash's DHCP for Netboot. Beta 0.0.4\n");
    Checkargc(args,argc);
    BOOTPServer();
}

/*Hash_Define*/
