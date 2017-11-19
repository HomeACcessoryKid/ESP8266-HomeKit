/*
 *  Copyright 2016 HomeACcessoryKid - HacK - homeaccessorykid@gmail.com
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef __HK_H__
#define __HK_H__

#include "wolfssl/wolfcrypt/chacha20_poly1305.h"
#include "cJSON.h"
#include "hkc.h"

//#define DEMO
//#define FACTORY  //also allow the url http://my.ip.address.numeric:661/factory once paired
#define DEBUG0
#define DEBUG1
#define DEBUG2
#define DEBUG3
#define DEBUG4
//#define DEBUG5
//#define DEBUG6
//#define DEBUG7
//#define DEBUG8
//#define DEBUG9

#define PASSWORD "031-45-154"
#define PASSWORD_LEN 10

#define BOOLEAN "bool"
#define STRING  "string"
#define INT     "int"
#define UINT8   "uint8"
#define UINT16  "uint16"
#define UINT32  "uint32"
#define UINT64  "uint64"
#define FLOAT   "float"
#define TLV8    "tlv8"
#define DATA    "data"

#define TLVNUM 12
#define ANLMAX 32 //accessorynamelengthmax
#define SECTOR 0x7A
#define START SECTOR*0x1000

typedef struct _espconn_msg{
    struct espconn *pespconn;
    void *pcommon; //at least that is what I suspect
    int rport;
    uint8 rip[4];
    void *p05;
    void *p06;
    void *p07;
    void *p08;
    void *p09;
    void *p10;
    void *p11;
    void *p12;
    int i13;
    void *p14;
    void *p15;
    void *p16;
    void *p17;
    void *p18;
    int i19;
    void *p20;
    void *p21;
    void *p22;
    void *preverse;
    void *pssl;
    struct _espconn_msg *pnext;
    void *p26;
    void *p27;
    int i28;
}espconn_msg;/**/

typedef struct _crypto_parm {
    xSemaphoreHandle semaphore;
    struct espconn  *pespconn;
    int             state;
    int             stale;
    uint32_t        connectionid;
    int             encrypted;
    long            countwr;
    long            countrd;
    word32          sessionkey_len;
    byte            sessionkey[32];
    byte            verKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    byte            readKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    byte            writeKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    char            object[0x1cb];
    int             objects_len[TLVNUM];
} crypto_parm;
/*
int objects_maxlen[TLVNUM] = {1,0x50,0,0x180,0x40,0xd0,1,0,0,0,0x40,9}; //global
//old system, now all in one object array
char object3[0x180]; //reuse for object10, object 1 and object5
//char object10[0x40]; //overlap object3 from 0x20
//char object1[0x50]; //overlap object3 from 0x60 //36 is enough
//char object5[0xd0]; //overlap object3 from 0xb0 //154 is enough
char object4[0x40]; //make dynamic memory during pair-setup
char object0[1];
char object6[1];
char object11[9]; //for invited persons //normally length 1??
char *objects[TLVNUM] = {object0,object3+0x60,NULL,object3,object4,object3+0xb0,object6,NULL,NULL,NULL,object3+0x20,object11};/**/
//new system
/*char object[0x1cb];
char *objects[TLVNUM] = {object+0x1c0,object+0x60,NULL,object,object+0x180,object+0xb0,object+0x1c1,NULL,NULL,NULL,object+0x20,object+0x1c2};
int objects_len[TLVNUM];/**/
//XXXXXXXXXXXXX recreate objects and objects_len inside each routine, using object from crypto_parm

#define URLSize 64

typedef enum Result_Resp {
    RespFail = 0,
    RespSuc,
} Result_Resp;

typedef enum ProtocolType {
    GET = 0,
    POST,
    PUT,
} ProtocolType;

typedef enum _ParmType {
    SWITCH_STATUS = 0,
    INFOMATION,
    WIFI,
    SCAN,
    REBOOT,
    DEEP_SLEEP,
    LIGHT_STATUS,
    CONNECT_STATUS,
    USER_BIN
} ParmType;

typedef struct URL_Frame {
    enum ProtocolType Type;
    char pSelect[URLSize];
    char pCommand[URLSize];
    char pFilename[URLSize];
} URL_Frame;

typedef struct _rst_parm {
    ParmType parmtype;
    struct espconn *pespconn;
} rst_parm;


void    new_ip(void *arg);

void    json_init(void *arg);

char    *parse_cgi(char *in);

void    parse_chas(void *arg, char *json);

void    crypto_prepare(void *arg);

void    crypto_init();

void    crypto_setup1(void *arg);

void    crypto_setup3(void *arg);

void    crypto_setup5(void *arg);

void    crypto_verify1(void *arg);

void    crypto_verify3(void *arg);

void    crypto_tasks();

void    pairadd(void *arg);

void    pairdel(void *arg);

void    decrypt(void *arg, char *data, unsigned short *length);

void    encrypt(void *arg, char *data, unsigned short *length);

/******************************************************************************
 * FunctionName : tlv8_parse
 * Description  : take incoming buffer and deliver tlv structure array
 * Parameters   : pbuf -- pointer to buffer
 *                len -- the length of the buffer
 *                objects -- the pointer to the struct array
*                 objects_len -- array of lengths of the struct
 * Returns      :
*******************************************************************************/
void    tlv8_parse(char *pbuf, uint16 len, char *objects[], int objects_len[]);

/******************************************************************************
 * FunctionName : tlv8_add
 * Description  : adds one item to buffer in chunked and tlv8 encoding
 * Parameters   : pbuf -- pointer to buffer
 *                index -- distance to buffer insertion point will be updated
 *                type -- type of item to add
 *                len -- the length of the value to add (max 4094)
 *                value -- pointer to buffer with value content
 * Returns      :
*******************************************************************************/
void    tlv8_add(char *pbuf, uint16 *index, int type, uint16 len, char *value);

/******************************************************************************
 * FunctionName : tlv8_close
 * Description  : add the final chunked close item of zero length
 * Parameters   : pbuf -- pointer to buffer
 *                index -- distance to buffer insertion point will be updated
 * Returns      :
*******************************************************************************/
void    tlv8_close(char *pbuf, uint16 *index);

void    event_send(void *arg, char *psend);

void    tlv8_send(void *arg, char *pbuf, uint16 len);

void    server_init(uint32 port);

#endif
