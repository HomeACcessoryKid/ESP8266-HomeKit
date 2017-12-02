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

/*
 * ESPRSSIF MIT License
 *
 * Copyright (c) 2015 <ESPRESSIF SYSTEMS (SHANGHAI) PTE LTD>
 *
 * Permission is hereby granted for use on ESPRESSIF SYSTEMS ESP8266 only, in which case,
 * it is free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "stdarg.h"
#include "esp_common.h"
#include "espconn.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/srp.h"
#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/chacha.h"
#include "wolfssl/wolfcrypt/poly1305.h"
#include "wolfssl/wolfcrypt/chacha20_poly1305.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include <wolfssl/wolfcrypt/error-crypt.h>
#include "hk.h"

#define NLEN    384
#define MAXITM   31

extern  espconn_msg *plink_active;
//below the global struct for the acc_items
acc_item    acc_items[MAXITM+1];
cJSON       *root;
struct      espconn hkcesp_conn;
os_timer_t  browse_timer;
xSemaphoreHandle    cid_semaphore = NULL;
xQueueHandle        crypto_queue;

LOCAL   char    *precvbuffer;
static  uint32  dat_sumlength = 0;

byte    myUsername[18];     //global
word32  myUsername_len=17;  //global
byte    myACCname[ANLMAX+1];

int     objects_maxlen[TLVNUM]= {1,0x50,0,0x180,0x40,0xd0,1,0,0,0,0x40,9}; //global

ed25519_key     myKey; //global
Srp             srp;

int     pairing=0,halfpaired=0;

byte two[]= {0x02};
byte four[]={0x04};
byte six[]= {0x06};

byte B[]={  //initialize it with value of N
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2,
  0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
  0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
  0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
  0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
  0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
  0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9,
  0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
  0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11,
  0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d,
  0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36,
  0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
  0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56,
  0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d,
  0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08,
  0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46, 0x2e, 0x36, 0xce, 0x3b,
  0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03, 0x9b, 0x27, 0x83, 0xa2,
  0xec, 0x07, 0xa2, 0x8f, 0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9,
  0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7c,
  0xea, 0x95, 0x6a, 0xe5, 0x15, 0xd2, 0x26, 0x18, 0x98, 0xfa, 0x05, 0x10,
  0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xaa, 0xc4, 0x2d, 0xad, 0x33, 0x17, 0x0d,
  0x04, 0x50, 0x7a, 0x33, 0xa8, 0x55, 0x21, 0xab, 0xdf, 0x1c, 0xba, 0x64,
  0xec, 0xfb, 0x85, 0x04, 0x58, 0xdb, 0xef, 0x0a, 0x8a, 0xea, 0x71, 0x57,
  0x5d, 0x06, 0x0c, 0x7d, 0xb3, 0x97, 0x0f, 0x85, 0xa6, 0xe1, 0xe4, 0xc7,
  0xab, 0xf5, 0xae, 0x8c, 0xdb, 0x09, 0x33, 0xd7, 0x1e, 0x8c, 0x94, 0xe0,
  0x4a, 0x25, 0x61, 0x9d, 0xce, 0xe3, 0xd2, 0x26, 0x1a, 0xd2, 0xee, 0x6b,
  0xf1, 0x2f, 0xfa, 0x06, 0xd9, 0x8a, 0x08, 0x64, 0xd8, 0x76, 0x02, 0x73,
  0x3e, 0xc8, 0x6a, 0x64, 0x52, 0x1f, 0x2b, 0x18, 0x17, 0x7b, 0x20, 0x0c,
  0xbb, 0xe1, 0x17, 0x57, 0x7a, 0x61, 0x5d, 0x6c, 0x77, 0x09, 0x88, 0xc0,
  0xba, 0xd9, 0x46, 0xe2, 0x08, 0xe2, 0x4f, 0xa0, 0x74, 0xe5, 0xab, 0x31,
  0x43, 0xdb, 0x5b, 0xfc, 0xe0, 0xfd, 0x10, 0x8e, 0x4b, 0x82, 0xd1, 0x20,
  0xa9, 0x3a, 0xd2, 0xca, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
word32  B_len=NLEN;

struct  espconn user_udp_espconn;
char mdns[] = {
    0x00, 0x00, 0x84, 0x00,
    0x00, 0x00, 0x00, 0x05, // 5 answers
    0x00, 0x00, 0x00, 0x00, // 0 additional records                                                       //haptcplocal
    0x04, 0x5f, 0x68, 0x61, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, //@12
    0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x94,                         //PTR, IN, TTL                //@29
    0x00,       0x23, 0x20,                                                 //>anl+3@38*1                 //>anl@39*1
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,       //>accname@40*anl
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
    0xc0, 0x0c,                                                             //referral to _hap._tcp.local //@anl+40
    0xc0, 0x27,                                                             //referral to accname         //@anl+42
    0x00, 0x10, 0x80, 0x01, 0x00, 0x00, 0x11, 0x94,                         //TXT, INflush, 4500s         //@anl+44
    0x00,       0x59,                                                                                     //>anl+57@anl+53*1
    0x23,       0x6d, 0x64, 0x3d,                                           //md=                         //>anl+3@anl+54*1
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,       //>accname@anl+58*anl
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
    0x06, 0x70, 0x76, 0x3d, 0x31, 0x2e, 0x30,                               //pv=1.0                      //@2anl+58
    0x14, 0x69, 0x64, 0x3d,                                                 //id=                         //@2anl+65
    0x30, 0x30, 0x3a, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x3a, 0x30, 0x30, //>myUserName@2anl+69*17
    0x04, 0x63, 0x23, 0x3d, 0x31, 0x04, 0x73, 0x23, 0x3d, 0x31, 0x04, 0x66, 0x66, 0x3d, 0x30,//c#, s#, ff //@2anl+86
    0x04, 0x63, 0x69, 0x3d, 0x31,                                           //ci                          //>ci@2anl+105*1
    0x04, 0x73, 0x66, 0x3d, 0x30,                                           //sf                          //>pairing@2anl+110*1
    0xc0, 0x27,                                                             //referal to accname          //@2anl+111
    0x00, 0x21, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x1d,             //SRV, INflush, 120s len29    //@2anl+113
    0x00, 0x00, 0x00, 0x00,       0x02, 0x95,                               //prio, weight,               //>TCPport@2anl+127*2
    0x14, 0x48, 0x4b, 0x5f,                                                 //HK_mac                      //@2anl+129
    0x30, 0x30, 0x3a, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x3a, 0x30, 0x30, 0x3a, 0x30, 0x30, //>myUserName@2anl+133*17
    0xc0, 0x16,                                                             //referral to .local          //@2anl+150
    0xc0, 0xc1,                                                             //referral to HK_mac          //>2anl+129@2anl+153*1
    0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04,             //A, INflush, 120s, len4      //@2anl+154
    0x00, 0x00, 0x00, 0x00,                                                 //IP address                  //>IP@2anl+164*4
    0x09, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73,                   //_services             //@2anl+168 last 37 bytes
    0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64, 0x04, 0x5f, 0x75, 0x64, 0x70, //.dns-sd._udp          //@2anl*178
    0xc0, 0x16,                                                                   //referral to .local    //@2anl+191
    0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x02,                   //PTR, IN, 4500s, len2  //@2anl+193
    0xc0, 0x0c                                                              //referral to haptcplocal     //@2anl+203
 };
 unsigned int   mdns_len=2*ANLMAX+205;
 int            anl=ANLMAX;
 int            ready=0; //replace by semafore

/*---------------------------------------------------------------------------*/

void    print_mem(void const *vp, size_t after, size_t before)
{
    char        a[12];
    unsigned char const *p = vp;
    size_t i;
    p-=before;
    for (i=0; i<after+before; i+=4) {
        sprintf(a,"%x: ",p+i);
        os_printf("%s%02x%02x%02x%02x%s", i%40==0 ? a : "",p[i+3],p[i+2],p[i+1],p[i], i % 40 == 36 ? "\n" :  " ");
    }
    os_printf("\n");
}

void    json_init(void *arg)
{
    hkc_user_init(myACCname);
    ready=1;
    #ifdef DEBUG4   
    os_printf("ready @ %d\n",system_get_time()/1000);
    #endif
    vTaskDelete(NULL);
}

char    *parse_cgi(char *in) //take aid.iid string and return chars string / only single digit aid!
{
    char *out;
    cJSON *chars,*items,*item;
    int aid, iid;

    chars=cJSON_CreateObject();
    cJSON_AddItemToObject( chars, "characteristics", items=cJSON_CreateArray()); //consider a addAccessory function
    out=strtok(in,",");
    while( out ) {
        aid=out[0]-0x30; //only supporting single digit aid
        iid=atoi(out+2);
        //callback update
        if (acc_items[iid].change_cb) acc_items[iid].change_cb(aid, iid, cJSON_GetObjectItem(acc_items[iid].json,"value"),2); //2 is for update
        cJSON_AddItemToArray(items,item=cJSON_CreateObject());
        cJSON_AddNumberToObject(item, "aid",  aid );
        cJSON_AddNumberToObject(item, "iid",  iid );
        cJSON_AddItemReferenceToObject(item, "value", cJSON_GetObjectItem(acc_items[iid].json,"value"));//crash if points to null?
        out=strtok(NULL,",");
    }
    out=cJSON_PrintUnformatted(chars);
    cJSON_Delete(chars);
    return out;
}

void    change_value(int aid, int iid, cJSON *item)
{
    cJSON   *value;
    char *format;

    format=cJSON_GetObjectItem(acc_items[iid].json,"format")->valuestring;
    value=cJSON_GetObjectItem(acc_items[iid].json,"value");
//  print_mem(item ,64);
//  print_mem(value,64);
//  os_printf("value: %08x ",value);
    switch (item->type) {
        case cJSON_Number: {
            #ifdef DEBUG0
            os_printf("chas: %d.%d=valN -> %s\n",aid,iid,format);
            #endif
            if (value && !strcmp(format,BOOLEAN)) {
                if (item->valueint==0)value->type=0; else value->type=1;
            } else if(value && (!strcmp(format,INT) || !strcmp(format,UINT8) || !strcmp(format,UINT16) || !strcmp(format,UINT32) || !strcmp(format,UINT64) || !strcmp(format,FLOAT))) {
                value->valueint   =item->valueint;
                value->valuedouble=item->valuedouble;
            }
        } break;
        case cJSON_String: {
            #ifdef DEBUG0
            os_printf("chas: %d.%d=valS -> %s\n",aid,iid,format);
            #endif
            if (value && (!strcmp(format,STRING) || !strcmp(format,TLV8) || !strcmp(format,DATA))) {
                format=value->valuestring;
                value->valuestring=item->valuestring;
                item->valuestring=format;
            }
        } break;
        case cJSON_False: {
            #ifdef DEBUG0
            os_printf("chas: %d.%d=valF -> %s\n",aid,iid,format);
            #endif
            if (value && !strcmp(format,BOOLEAN)) value->type=0;
        } break;
        case cJSON_True: {
            #ifdef DEBUG0
            os_printf("chas: %d.%d=valT -> %s\n",aid,iid,format);
            #endif
            if (value && !strcmp(format,BOOLEAN)) value->type=1;
        } break;
        default: {
            #ifdef DEBUG0
            os_printf("chas: %d.%d=valX -> %s\n",aid,iid,format);
            #endif
        } break;
    }
}

void    send_events(void *arg, int aid, int iid)
{
    espconn_msg *plist = NULL;
    plist = plink_active;
    crypto_parm *pcryp = arg;
    struct espconn *pespconn = NULL;
    char *json;
    char tag[5];

    if (pcryp) pespconn=pcryp->pespconn;
    
    while(plist != NULL){
        if ( (plist->pespconn!=pespconn) && //do not send to self!
                    (pcryp=plist->pespconn->reserve) &&  //does it have a valid pointer
                    (pcryp->connectionid&acc_items[iid].events) ) { //compare bitmaps
            if (xSemaphoreTake(pcryp->semaphore,5)) { //if busy, wait up till 50ms
                sprintf(tag,"%d.%d",aid,iid);
                //os_printf("send an event to conn %02x for tag:%s\n",pcryp->connectionid,tag);
                json=parse_cgi(tag);
                event_send(pcryp,json);
                free(json);
                xSemaphoreGive(pcryp->semaphore);
            }
        }
        plist = plist->pnext;
    }
}

//parse this: {"characteristics":[{"aid":1,"iid":9,"ev":false},{"aid":1,"iid":12,"ev":false}]}
//and   this: {"characteristics":[{"aid":1,"iid":9,"value":0},{"aid":1,"iid":12,"value":100}]}
void    parse_chas(void *arg, char *in)
{
    crypto_parm *pcryp = arg;
    cJSON   *json,*chas,*cha,*item;
    int i,aid,iid;

    json=   cJSON_Parse(in);
    chas=   cJSON_GetObjectItem(json,"characteristics"); //this is an array
    for (i=0;i<cJSON_GetArraySize(chas);i++) {
        cha=cJSON_GetArrayItem(chas,i);
        aid=cJSON_GetObjectItem(cha,"aid")->valueint;
        iid=cJSON_GetObjectItem(cha,"iid")->valueint;
        #ifdef DEBUG4
        os_printf("aid=%d,iid=%d\n",aid,iid);
        #endif
        
        if (item=cJSON_GetObjectItem(cha,"ev")) {
            switch (item->type) {
                case cJSON_False: {
                    #ifdef DEBUG0
                    os_printf("chas: %d.%d=evF",aid,iid);
                    #endif
                    acc_items[iid].events&=~pcryp->connectionid;
                } break;
                case cJSON_True: {
                    #ifdef DEBUG0
                    os_printf("chas: %d.%d=evT",aid,iid);
                    #endif
                    acc_items[iid].events|=pcryp->connectionid;
                } break;
                default: {
                    #ifdef DEBUG0
                    os_printf("chas: %d.%d=evX",aid,iid);
                    #endif
                } break;
            }
            #ifdef DEBUG4
            os_printf("  events: %02x\n",acc_items[iid].events);
            #endif
        }
        if (item=cJSON_GetObjectItem(cha,"value")) {
            #ifdef DEBUG4
            char *out;
            out=cJSON_Print(acc_items[iid].json);   os_printf("%08x: %s\n",acc_items[iid].json,out);    free(out);  // Print to text, print it, release the string.
            #endif
            
            //set the value in the master json
            change_value(aid, iid, item);
            
            #ifdef DEBUG4
            out=cJSON_Print(acc_items[iid].json);   os_printf("%08x: %s\n",acc_items[iid].json,out);    free(out);  // Print to text, print it, release the string.
            #endif
            
            //send out events to subscribed connections
            send_events(pcryp,aid,iid);
            //call the callback function if it exists
            if (acc_items[iid].change_cb) acc_items[iid].change_cb(aid, iid, cJSON_GetObjectItem(acc_items[iid].json,"value"),1); //1 is for push change
        }
    }
    cJSON_Delete(json);
}

cJSON   *initAccessories()
{
    cJSON   *accs;
    
    memset(acc_items,0,sizeof(acc_items));
    root=cJSON_CreateObject();
    cJSON_AddItemToObject( root, "accessories", accs=cJSON_CreateArray());

    return accs;
}

cJSON   *addAccessory(cJSON *accs, int aid)
{
    cJSON *acc,*sers;
    
    cJSON_AddItemToArray(accs,acc=cJSON_CreateObject());
    cJSON_AddNumberToObject(acc, "aid",  aid );
    cJSON_AddItemToObject(  acc, "services", sers=cJSON_CreateArray());
    
    return sers;
}

cJSON   *addService(cJSON *services, int iid, char *brand, int sType)
{
    cJSON *service,*characteristics;
    char longid[37];
    
    sprintf(longid,brand,sType);
    cJSON_AddItemToArray(services,service=cJSON_CreateObject());
    cJSON_AddNumberToObject(service, "iid",  iid );
    cJSON_AddStringToObject(service, "type", longid  );
    cJSON_AddItemToObject(  service, "characteristics", characteristics=cJSON_CreateArray());
    
    return characteristics;
}

void    addCharacteristic(cJSON *characteristics, int aid, int iid, char *brand, int cType, char *valuestring, acc_cb change_cb)
{
    cJSON *perms,*valid_values,*value=NULL;
    char longid[37],format[7];
    int perm, maxlen, intval;
    
    sprintf(longid,brand,cType);
    cJSON_AddItemToArray(   characteristics,acc_items[iid].json=cJSON_CreateObject());
    cJSON_AddNumberToObject(acc_items[iid].json, "iid",  iid );
    cJSON_AddStringToObject(acc_items[iid].json, "type", longid );
    cJSON_AddItemToObject(  acc_items[iid].json, "perms", perms=cJSON_CreateArray());
    //cJSON_AddFalseToObject( acc_items[iid].json, "bonjour");
    //from id pick up specific settings
    switch (cType) {
        case BRIGHTNESS_C: {
            strcpy(format,INT);         perm=7;     maxlen=0;
            cJSON_AddNumberToObject(acc_items[iid].json, "minValue",   0);
            cJSON_AddNumberToObject(acc_items[iid].json, "maxValue", 100);
            cJSON_AddNumberToObject(acc_items[iid].json, "minStep",    1);
            cJSON_AddStringToObject(acc_items[iid].json, "unit", "percentage");
        } break;
        case CURRENT_HEATING_COOLING_STATE_C:{
            strcpy(format,UINT8);        perm=5;
            cJSON_AddNumberToObject(acc_items[iid].json, "minValue",   0);
            cJSON_AddNumberToObject(acc_items[iid].json, "maxValue",   2);
            cJSON_AddNumberToObject(acc_items[iid].json, "minStep",    1);
            cJSON_AddItemToObject(acc_items[iid].json, "valid-values", valid_values=cJSON_CreateArray());  
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(0));       
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(1)); 
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(2));        
        } break;
        case CURRENT_TEMPERATURE_C:{
            strcpy(format,FLOAT);        perm=5;
            cJSON_AddNumberToObject(acc_items[iid].json, "minValue",   0);
            cJSON_AddNumberToObject(acc_items[iid].json, "maxValue",   100);
            cJSON_AddNumberToObject(acc_items[iid].json, "minStep",    0.1);
            cJSON_AddStringToObject(acc_items[iid].json, "unit", "celsius");   
        } break;
        case HUE_C: {
            strcpy(format,FLOAT);     perm=7;
            cJSON_AddNumberToObject(acc_items[iid].json, "minValue",   0);
            cJSON_AddNumberToObject(acc_items[iid].json, "maxValue",   360);
            cJSON_AddNumberToObject(acc_items[iid].json, "minStep",    1);
            cJSON_AddStringToObject(acc_items[iid].json, "unit", "arcdegrees"); 
        } break;
        case IDENTIFY_C: {
            strcpy(format,BOOLEAN);     perm=2;     maxlen=1;
        } break;
        case MANUFACTURER_C: {
            strcpy(format,STRING);      perm=4;     maxlen=64;
        } break;
        case MODEL_C: {
            strcpy(format,STRING);      perm=4;     maxlen=64;
        } break;
        case MOTION_DETECTED_C: {
            strcpy(format,BOOLEAN);      perm=5;     maxlen=1;
        } break;
        case NAME_C: {
            strcpy(format,STRING);      perm=4;     maxlen=64;
        } break;
        case ON_C: {
            strcpy(format,BOOLEAN);     perm=7;     maxlen=1;
        } break;
        case ROTATION_DIRECTION_C: {
            strcpy(format,INT);     perm=7;
            cJSON_AddNumberToObject(acc_items[iid].json, "minValue",   0);
            cJSON_AddNumberToObject(acc_items[iid].json, "maxValue",   1);
            cJSON_AddNumberToObject(acc_items[iid].json, "minStep",    1); 
            cJSON_AddItemToObject(acc_items[iid].json, "valid-values", valid_values=cJSON_CreateArray());  
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(0));       
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(1)); 
        } break;
        case ROTATION_SPEED_C: {
            strcpy(format,FLOAT);     perm=7;
            cJSON_AddNumberToObject(acc_items[iid].json, "minValue",   0);
            cJSON_AddNumberToObject(acc_items[iid].json, "maxValue",   100);
            cJSON_AddNumberToObject(acc_items[iid].json, "minStep",    1);
            cJSON_AddStringToObject(acc_items[iid].json, "unit", "percentage"); 
        } break;
        case SATURATION_C: {
            strcpy(format,FLOAT);     perm=7;
            cJSON_AddNumberToObject(acc_items[iid].json, "minValue",   0);
            cJSON_AddNumberToObject(acc_items[iid].json, "maxValue",   100);
            cJSON_AddNumberToObject(acc_items[iid].json, "minStep",    1);
            cJSON_AddStringToObject(acc_items[iid].json, "unit", "percentage"); 
        } break;
        case SERIAL_NUMBER_C: {
            strcpy(format,STRING);      perm=4;     maxlen=64;
        } break;
        case TARGET_HEATING_COOLING_STATE_C:{
            strcpy(format,UINT8);        perm=7;
            cJSON_AddNumberToObject(acc_items[iid].json, "minValue",   0);
            cJSON_AddNumberToObject(acc_items[iid].json, "maxValue",   3);
            cJSON_AddNumberToObject(acc_items[iid].json, "minStep",    1);
            cJSON_AddItemToObject(acc_items[iid].json, "valid-values", valid_values=cJSON_CreateArray());  
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(0));       
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(1)); 
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(2));   
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(3));     
        } break;
        case TARGET_TEMPERATURE_C:{
            strcpy(format,FLOAT);        perm=7;
            cJSON_AddNumberToObject(acc_items[iid].json, "minValue",   10);
            cJSON_AddNumberToObject(acc_items[iid].json, "maxValue",   38);
            cJSON_AddNumberToObject(acc_items[iid].json, "minStep",    0.1);
            cJSON_AddStringToObject(acc_items[iid].json, "unit", "celsius");   
        } break;
        case TEMPERATURE_DISPLAY_UNITS_C:{
            strcpy(format,UINT8);        perm=7;
            cJSON_AddNumberToObject(acc_items[iid].json, "minValue",   0);
            cJSON_AddNumberToObject(acc_items[iid].json, "maxValue",   1);
            cJSON_AddNumberToObject(acc_items[iid].json, "minStep",    1); 
            cJSON_AddItemToObject(acc_items[iid].json, "valid-values", valid_values=cJSON_CreateArray());  
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(0));       
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(1));  
        } break;
        case CARBON_MONOXIDE_DETECTED_C:{
            strcpy(format,UINT8);        perm=5;
            cJSON_AddNumberToObject(acc_items[iid].json, "minValue",   0);
            cJSON_AddNumberToObject(acc_items[iid].json, "maxValue",   1);
            cJSON_AddNumberToObject(acc_items[iid].json, "minStep",    1); 
            cJSON_AddItemToObject(acc_items[iid].json, "valid-values", valid_values=cJSON_CreateArray());  
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(0));       
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(1)); 
        } break;
        case CURRENT_AMBIENT_LIGHT_LEVEL_C:{
            strcpy(format,FLOAT);        perm=5;
            cJSON_AddNumberToObject(acc_items[iid].json, "minValue",   0.0001);
            cJSON_AddNumberToObject(acc_items[iid].json, "maxValue",   100000);
            cJSON_AddStringToObject(acc_items[iid].json, "unit", "lux"); 
        } break;
        case STATUS_ACTIVE_C:
            strcpy(format,BOOLEAN);      perm=5;
        case STATUS_TAMPERED_C:{
            strcpy(format,UINT8);        perm=5;
            cJSON_AddNumberToObject(acc_items[iid].json, "minValue",   0);
            cJSON_AddNumberToObject(acc_items[iid].json, "maxValue",   1);
            cJSON_AddNumberToObject(acc_items[iid].json, "minStep",    1); 
            cJSON_AddItemToObject(acc_items[iid].json, "valid-values", valid_values=cJSON_CreateArray());  
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(0));       
            cJSON_AddItemToArray(valid_values,cJSON_CreateNumber(1)); 
        } break;
        default: {
            
        } break;
    }
    cJSON_AddStringToObject(acc_items[iid].json, "format", format);
    if (maxlen) {
        if(!strcmp(format,STRING))
            cJSON_AddNumberToObject(acc_items[iid].json, "maxLen", maxlen );
        else if (!strcmp(format,DATA))
            cJSON_AddNumberToObject(acc_items[iid].json, "maxDataLen", maxlen );
    }
    //encode perms like rwe octal
    if (perm & 2) cJSON_AddItemToArray(perms,cJSON_CreateString("pw"));
    if (perm & 4) cJSON_AddItemToArray(perms,cJSON_CreateString("pr"));
    if (perm & 1) {
        cJSON_AddItemToArray(perms, cJSON_CreateString("ev"));
        cJSON_AddTrueToObject( acc_items[iid].json, "events");
    }
    //addItem(aid,iid,format,valuestring,change_cb);
    if (valuestring) {
        if (!strcmp(format,BOOLEAN)){
            if ( !strcmp(valuestring,"0") || !strcmp(valuestring,"false") ) intval=0; else intval=1;
            cJSON_AddItemToObject(acc_items[iid].json, "value", value=cJSON_CreateBool(intval) );
        }
        if (!strcmp(format,STRING) || !strcmp(format,TLV8) || !strcmp(format,DATA) ){
            cJSON_AddItemToObject(acc_items[iid].json, "value", value=cJSON_CreateString(valuestring) );
        }
        if (!strcmp(format,INT) || !strcmp(format,UINT8) || !strcmp(format,UINT16) || !strcmp(format,UINT32) || !strcmp(format,UINT64)){
            cJSON_AddItemToObject(acc_items[iid].json, "value", value=cJSON_CreateNumber(atoi(valuestring)) );
        }
        if (!strcmp(format,FLOAT)){
            cJSON_AddItemToObject(acc_items[iid].json, "value", value=cJSON_CreateNumber(atof(valuestring)) );
        }
    }
    acc_items[iid].change_cb= (acc_cb) change_cb;
    if (change_cb) change_cb(aid,iid,value,0); //0 is initialize
}


/******************************************************************************
 * FunctionName : espconn_browse
 * Description  : run all open connections of the server
 * Parameters   : arg -- pointer to the espconn used for espconn_connect
 * Returns      : none
*******************************************************************************/
void espconn_browse(void *arg)
{
    #ifdef DEBUG0
    espconn_msg *plist = NULL;
    plist = plink_active;
    struct espconn *pespconn = arg;
    crypto_parm *pcryp;
    int iid,linefeed=0;
    
    while(plist != NULL){  //if(plist->preverse == pespconn) to select a particular socket
        if (pcryp=plist->pespconn->reserve) {
            os_printf("%08x conn, rev:%08x, nxt:%08x, act:%d, %d.%d.%d.%d:%d, cid:%02x\n", \
                    plist->pespconn,plist->preverse,plist->pnext,plist->pespconn->state, \
                    plist->rip[0],plist->rip[1],plist->rip[2],plist->rip[3],plist->rport,pcryp->connectionid);
        }
        plist = plist ->pnext;
    }
    for (iid=1;iid<MAXITM+1;iid++) if(acc_items[iid].events) {os_printf("ev1.%d:%02x | ",iid,acc_items[iid].events);linefeed=1;}
    if (linefeed) os_printf("\n");

    os_timer_disarm(&browse_timer);
    os_timer_setfn(&browse_timer, (os_timer_func_t *)espconn_browse, arg);
    os_timer_arm(&browse_timer, 12000, 0);
    #endif
}
    
/******************************************************************************
 * FunctionName : parse_url
 * Description  : parse the received data from the server
 * Parameters   : precv -- the received data
 *                purl_frame -- the result of parsing the url
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
parse_url(char *precv, URL_Frame *purl_frame)
{
    char *str = NULL;
    uint8 length = 0;
    char *pbuffer = NULL;
    char *pbufer = NULL;

    if (purl_frame == NULL || precv == NULL) {
        return;
    }

    pbuffer = (char *)strstr(precv, "Host:");

    if (pbuffer != NULL) {
        length = pbuffer - precv;
        pbufer = (char *)zalloc(length + 1);
        pbuffer = pbufer;
        memcpy(pbuffer, precv, length);
        memset(purl_frame->pSelect, 0, URLSize);
        memset(purl_frame->pCommand, 0, URLSize);
        memset(purl_frame->pFilename, 0, URLSize);

        if (strncmp(pbuffer, "GET ", 4) == 0) {
            purl_frame->Type = GET;
            pbuffer += 4;
        } else if (strncmp(pbuffer, "POST ", 5) == 0) {
            purl_frame->Type = POST;
            pbuffer += 5;
        } else if (strncmp(pbuffer, "PUT ", 4) == 0) {
            purl_frame->Type = PUT;
            pbuffer += 4;
        }

        pbuffer ++; // to skip the /
        str = (char *)strstr(pbuffer, "?");

        if (str != NULL) {
            length = str - pbuffer;
            memcpy(purl_frame->pSelect, pbuffer, length);
            str ++;
            pbuffer = (char *)strstr(str, "=");

            if (pbuffer != NULL) {
                length = pbuffer - str;
                memcpy(purl_frame->pCommand, str, length);
                pbuffer ++;
                str = (char *)strstr(pbuffer, "&");

                if (str != NULL) {
                    length = str - pbuffer;
                    memcpy(purl_frame->pFilename, pbuffer, length);
                } else {
                    str = (char *)strstr(pbuffer, " HTTP");

                    if (str != NULL) {
                        length = str - pbuffer;
                        memcpy(purl_frame->pFilename, pbuffer, length);
                    }
                }
            }
        } else {
            str = (char *)strstr(pbuffer, " HTTP");

            if (str != NULL) {
                length = str - pbuffer;
                memcpy(purl_frame->pSelect, pbuffer, length);
            }
        }

        free(pbufer);
    } else {
        return;
    }
}

/******************************************************************************
 * FunctionName : save_data
 * Description  : put info in buffer
 * Parameters   : precv  -- data to save
 *                length -- The length of received data
 * Returns      : boolean if OK
*******************************************************************************/
LOCAL bool ICACHE_FLASH_ATTR
save_data(char *precv, uint16 length)
{
    bool flag = false;
    char length_buf[10] = {0};
    char *ptemp = NULL;
    char *pdata = NULL;
    uint16 headlength = 0;
    static uint32 totallength = 0;

    ptemp = (char *)strstr(precv, "\r\n\r\n");  //dangerous assumption in case of binary

    if (ptemp != NULL) {
        length -= ptemp - precv;
        length -= 4;
        totallength += length;
        headlength = ptemp - precv + 4;
        pdata = (char *)strstr(precv, "Content-Length: ");

        if (pdata != NULL) {
            pdata += 16;
            precvbuffer = (char *)strstr(pdata, "\r\n");

            if (precvbuffer != NULL) {
                memcpy(length_buf, pdata, precvbuffer - pdata);
                dat_sumlength = atoi(length_buf);
                #ifdef DEBUG1
                os_printf("dsl: %d, tl: %d, hl: %d, len: %d\n", dat_sumlength,totallength,headlength,length);
                #endif
            }
        } else {
            if (totallength != 0x00){
                totallength = 0;
                dat_sumlength = 0;
                return false;
            }
        }
        if ((dat_sumlength + headlength) >= 1024) { //protection to long packets???
            precvbuffer = (char *)zalloc(headlength + 1);
            memcpy(precvbuffer, precv, headlength + 1);  // only header copied
        } else {
            #ifdef DEBUG1
            os_printf("normal packet saved\n");
            #endif
            precvbuffer = (char *)zalloc(dat_sumlength + headlength + 1);
            //memcpy(precvbuffer, precv, strlen(precv));  //old version not binary proof
            memcpy(precvbuffer, precv, dat_sumlength + headlength);
        }
    } else {  // assuming a multipacket message
        #ifdef DEBUG1
        os_printf("multipacket extension saved\n");
        #endif
        if (precvbuffer != NULL) {
            totallength += length;
            memcpy(precvbuffer + strlen(precvbuffer), precv, length);  //not binary proof
        } else {
            totallength = 0;
            dat_sumlength = 0;
            return false;
        }
    }

    if (totallength == dat_sumlength) {
        totallength = 0;
        dat_sumlength = 0;
        return true;
    } else {
        return false;
    }
}

/******************************************************************************
 * FunctionName : check_data
 * Description  : verify if HTTP contentlength is OK
 * Parameters   : precv  -- data to verify
 *                length -- The length of received data
 * Returns      : boolean if OK
*******************************************************************************/
LOCAL bool ICACHE_FLASH_ATTR
check_data(char *precv, uint16 length)
{
    //bool flag = true;
    char length_buf[10] = {0};
    char *ptemp = NULL;
    char *pdata = NULL;
    char *tmp_precvbuffer;
    uint16 tmp_length = length;
    uint32 tmp_totallength = 0;
    
    ptemp = (char *)strstr(precv, "\r\n\r\n");
    
    if (ptemp != NULL) {
        tmp_length -= ptemp - precv;
        tmp_length -= 4;
        tmp_totallength += tmp_length;
        
        pdata = (char *)strstr(precv, "Content-Length: ");
        
        if (pdata != NULL){
            pdata += 16;
            tmp_precvbuffer = (char *)strstr(pdata, "\r\n");
            
            if (tmp_precvbuffer != NULL){
                memcpy(length_buf, pdata, tmp_precvbuffer - pdata);
                dat_sumlength = atoi(length_buf);
                #ifdef DEBUG1
                os_printf("A_dat:%u,tot:%u,lenght:%u\n",dat_sumlength,tmp_totallength,tmp_length);
                #endif
                if(dat_sumlength != tmp_totallength){
                    return false;
                }
            }
        }
    }
    return true;
}

/******************************************************************************
 * FunctionName : tlv8_send
 * Description  : processing the data as http format and send to the client or server; also frees the payload memory
 * Parameters   : arg -- argument to set for client or server
 *                psend -- The binary send data in chunked tlv8 format
 *                len -- the length of the send data
 * Returns      :
*******************************************************************************/
void ICACHE_FLASH_ATTR
tlv8_send(void *arg, char *pbuf, uint16 len)
{
    crypto_parm *pcryp = arg;
    int i;
    uint16 length = 0;
    char *psend = NULL;
    char httphead[] = "HTTP/1.1 200 OK\r\nContent-type: application/pairing+tlv8\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n";

    length = strlen(httphead) + len;
    psend = (char *)zalloc(length+1+18);
    memcpy(psend, httphead, strlen(httphead));
    memcpy(psend + strlen(httphead), pbuf, len);
    if (pbuf != NULL){  //consider to make calling party responsible
        free(pbuf);
        pbuf = NULL;
    }
    #ifdef DEBUG1
    for (i=0;i<length;i++) os_printf("%02x",psend[i]);
    os_printf("\nto be sent by tlv8_send routine\n");
    os_printf("arg=%08x, ptrespconn=%08x, pcryp=%08x\n",arg,pcryp->pespconn,pcryp);
    #endif
    // encrypt!
    if (pcryp->encrypted) encrypt(pcryp, psend, &length);
    if (!pcryp->stale){
        #ifdef DEBUG1
        os_printf("send result: %d\n",espconn_sent(pcryp->pespconn, psend, length));
        #else
        espconn_sent(pcryp->pespconn, psend, length);
        #endif
    }
    if (psend) {
        free(psend);
        psend = NULL;
    }
}

/******************************************************************************
 * FunctionName : acc_send
 * Description  : processing the data as http format and send to the client or server
 * Parameters   : arg -- argument to set for client or server
 * Returns      :
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
acc_send(void *arg)
{
    uint16 length = 0;
    uint16  len;
    char *pbuf = NULL;
    char httphead[128];
    char *accessories = NULL;
    crypto_parm *pcryp = arg;
    
    accessories=cJSON_PrintUnformatted(root);
    memset(httphead, 0, 128);
    len = strlen(accessories);
    sprintf(httphead, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: keep-alive\r\nContent-type: application/hap+json\r\n\r\n",len);
    length = strlen(httphead) + len;
    pbuf = (char *)zalloc(length + 1 + 54); //better calculate +18 per 0x400
    memcpy(pbuf, httphead, strlen(httphead));
    memcpy(pbuf + strlen(httphead), accessories, len);
    if (pcryp->encrypted) encrypt(pcryp, pbuf, &length);
    if (!pcryp->stale){
        #ifdef DEBUG1
        os_printf("length: 0x%04x\n",length);
        os_printf("Free heap:%d\n", system_get_free_heap_size());
        os_printf("send result: %d\n",espconn_sent(pcryp->pespconn, pbuf, length));
        #else
        espconn_sent(pcryp->pespconn, pbuf, length);
        #endif
    }
    
    if (pbuf) {
        free(pbuf);
        pbuf = NULL;
    }
    if (accessories) {
        free(accessories);
        accessories = NULL;
    }
}

/******************************************************************************
 * FunctionName : event_send
 * Description  : processing the data as http format and send to the client or server
 * Parameters   : arg -- argument to set for client or server
 *                psend -- The send data
 * Returns      :
*******************************************************************************/
void ICACHE_FLASH_ATTR
event_send(void *arg, char *psend)
{
    crypto_parm *pcryp = arg;
    uint16 length = 0;
    char *pbuf = NULL;
    char httphead[256];
    memset(httphead, 0, 256);

    sprintf(httphead, "EVENT/1.0 200 OK\r\nContent-type: application/hap+json\r\nContent-Length: %d\r\n\r\n", strlen(psend));

    length = strlen(httphead) + strlen(psend);
    pbuf = (char *)zalloc(length + 1 + 36); //better calculate +18 per 0x400
    memcpy(pbuf, httphead, strlen(httphead));
    memcpy(pbuf + strlen(httphead), psend, strlen(psend));

    if (pcryp->encrypted) encrypt(pcryp, pbuf, &length);
//  if (!pcryp->stale){
//      espconn_sent(pcryp->pespconn, pbuf, length);
//  }
    if (!pcryp->stale){
        if (pcryp->pespconn->state==ESPCONN_CONNECT) {
            espconn_sent(pcryp->pespconn, pbuf, length);
        } else {
            os_printf("event aborted\n");
        }
    }
    if (pbuf) {
        free(pbuf);
        pbuf = NULL;
    }
}/**/

/******************************************************************************
 * FunctionName : h204_send
 * Description  : processing the data as http format and send to the client or server
 * Parameters   : arg -- argument to set for client or server
 * Returns      :
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
h204_send(void *arg)
{
    crypto_parm *pcryp = arg;
    uint16 length = 0;
    char httphead[118]; //add 18 for encryption
    
    sprintf(httphead, "HTTP/1.1 204  No Content\r\nConnection: keep-alive\r\nContent-type: application/hap+json\r\n\r\n");
    length = strlen(httphead);
    if (pcryp->encrypted) encrypt(pcryp, httphead, &length);
    #ifdef DEBUG1
    os_printf("length: 0x%04x\n",length);
    os_printf("Free heap:%d\n", system_get_free_heap_size());
    os_printf("send result: %d\n",espconn_sent(pcryp->pespconn, httphead, length));
    #else
    espconn_sent(pcryp->pespconn, httphead, length);
    #endif
}

/******************************************************************************
 * FunctionName : data_send
 * Description  : processing the data as http format and send to the client or server
 * Parameters   : arg -- argument to set for client or server
 *                responseOK -- true or false
 *                psend -- The send data
 * Returns      :
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
data_send(void *arg, bool responseOK, char *psend)
{
    crypto_parm *pcryp = arg;
    uint16 length = 0;
    char *pbuf = NULL;
    char httphead[256];
    memset(httphead, 0, 256);

    if (responseOK) {
        sprintf(httphead,
                   "HTTP/1.0 200 OK\r\nContent-Length: %d\r\n",
                   psend ? strlen(psend) : 0);

        if (psend) {
            sprintf(httphead + strlen(httphead),
                       "Connection: keep-alive\r\nContent-type: application/hap+json\r\n\r\n");
            length = strlen(httphead) + strlen(psend);
            pbuf = (char *)zalloc(length + 1 + 36); //better calculate +18 per 0x400
            memcpy(pbuf, httphead, strlen(httphead));
            memcpy(pbuf + strlen(httphead), psend, strlen(psend));
        } else {
            sprintf(httphead + strlen(httphead), "\n");
            length = strlen(httphead);
        }
    } else {
        sprintf(httphead, "HTTP/1.0 400 BadRequest\r\n\
Content-Length: 0\r\nServer: lwIP/1.4.0\r\n\n");
        length = strlen(httphead);
    }

    if (psend) {
        if (pcryp->encrypted) encrypt(pcryp, pbuf, &length);
        espconn_sent(pcryp->pespconn, pbuf, length);
    } else {
        espconn_sent(pcryp->pespconn, httphead, length);
    }

    if (pbuf) {
        free(pbuf);
        pbuf = NULL;
    }
}

/******************************************************************************
 * FunctionName : response_send
 * Description  : processing the send result
 * Parameters   : arg -- argument to set for client or server
 *                responseOK --  true or false
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
response_send(void *arg, bool responseOK)
{
    data_send(arg, responseOK, NULL);
}

/******************************************************************************
 * FunctionName : server_recv
 * Description  : Processing the received data from the server
 * Parameters   : arg -- Additional argument to pass to the callback function
 *                pusrdata -- The received data (or NULL when the connection has been closed!)
 *                length -- The length of received data
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
server_recv(void *arg, char *pusrdata, unsigned short length)
{
    struct espconn *ptrespconn = arg;
    crypto_parm *pcryp = ptrespconn->reserve;
    if (pcryp && xSemaphoreTake(pcryp->semaphore,0)){
        #ifdef DEBUG1
        if ( xSemaphoreTake( pcryp->semaphore, ( portTickType ) 0 ) == pdFALSE) os_printf("p_sema locked\n");
        #endif
    
        char flash[]="killthesignature";
        int  *objects_len=pcryp->objects_len;
        char *objects[TLVNUM]= {pcryp->object+0x1c0,//0
                                pcryp->object+0x60, //1
                                NULL,
                                pcryp->object,      //3
                                pcryp->object+0x180,//4
                                pcryp->object+0xb0, //5
                                pcryp->object+0x1c1,//6
                                NULL,
                                NULL,
                                NULL,
                                pcryp->object+0x20, //10
                                pcryp->object+0x1c2 //11
        }; //read header file for above magic
        int i,datlen;
        URL_Frame *pURL_Frame = NULL;
        char *pParseBuffer = NULL;
        bool delegated=false,parse_flag = false;
        char *chars;
    
        #ifdef DEBUG0
        os_printf("server got a packet from %d.%d.%d.%d:%d at %d\n", ptrespconn->proto.tcp->remote_ip[0],
                    ptrespconn->proto.tcp->remote_ip[1],ptrespconn->proto.tcp->remote_ip[2],
                    ptrespconn->proto.tcp->remote_ip[3],ptrespconn->proto.tcp->remote_port,system_get_time()/1000);
        #endif

        #ifdef DEBUG1
//      os_printf("ServerRecvPriority:%d\n", uxTaskPriorityGet( NULL ));
        os_printf("len:%u\n",length);
        #endif
        if (pcryp->encrypted) decrypt(pcryp, pusrdata, &length); //length will be updated
        #ifdef DEBUG1
        os_printf("len:%u\n",length);
        #endif
        
        if(check_data(pusrdata, length) == false)
        {
        #ifdef DEBUG0
            os_printf("goto temp exit\n");
        #endif
             goto _temp_exit;
        }
        datlen=dat_sumlength;
        
        parse_flag = save_data(pusrdata, length);
        if (parse_flag == false) {
            response_send(pcryp, false);
        }

        //os_printf("dat_sumlength: %d\n",dat_sumlength);
        //for ( i=0; i<length ; i++ ) os_printf("%02x",precvbuffer[i]);
        //os_printf("\n");
        pURL_Frame = (URL_Frame *)zalloc(sizeof(URL_Frame));
        parse_url(precvbuffer, pURL_Frame);

        switch (pURL_Frame->Type) {
            case GET: {
                #ifdef DEBUG1
                //os_printf("Free heap:%d\n", system_get_free_heap_size());
                os_printf("GET/");
                os_printf("S: %s C: %s F: %s\n",pURL_Frame->pSelect,pURL_Frame->pCommand,pURL_Frame->pFilename);
                #endif

                if (strcmp(pURL_Frame->pSelect, "identify") == 0) {
                    #ifdef DEBUG1
                    os_printf("GET identify not yet implemented\n");
                    #endif
                    //do identify routine as a task
                    h204_send(pcryp);
                }
                if (strcmp(pURL_Frame->pSelect, "accessories") == 0 && pcryp->encrypted) {
                    #ifdef DEBUG1
                    os_printf("accessories\n");
                    #endif
                    if (halfpaired) {
                        #ifdef DEBUG1
                        os_printf("halfpaired\n");
                        #endif
                        flash[0]=0x00;flash[1]=0x7f;flash[2]=0xff;flash[3]=0xff;
                        spi_flash_write(START,(uint32 *)flash,4);
                        os_printf("postwrite\n");
                        halfpaired=0;
                        pairing=0;
                        xTaskCreate(new_ip,"newip",256,NULL,1,NULL); //send updated mdns sequence
                    }
                    pcryp->state=6;
                    xQueueSendToFront(crypto_queue,&pcryp,0);
                    delegated=true;
                    #ifdef DEBUG1
                    os_printf("out of TaskCreate - Free heap:%d\n", system_get_free_heap_size());
                    #endif
                }
                if (strcmp(pURL_Frame->pSelect, "characteristics") == 0 && strcmp(pURL_Frame->pCommand, "id") == 0 && pcryp->encrypted) {
                    #ifdef DEBUG1
                    os_printf("characteristics\n");
                    #endif
                    chars=parse_cgi(pURL_Frame->pFilename);
                    data_send(pcryp, true, chars);
                    free(chars);
                }
                #ifndef FACTORY
                if (pairing) {
                #endif
                    if (strcmp(pURL_Frame->pSelect, "factory") == 0 && !pcryp->encrypted) {
                        #ifdef DEBUG0
                        os_printf("factory reset\n");
                        #endif
                        spi_flash_write(START+4080,(uint32 *)flash,16); //mutilate the signature
                        system_restart();
                    }
                #ifndef FACTORY
                }
                #endif
//                 if (strcmp(pURL_Frame->pSelect, "client") == 0 && strcmp(pURL_Frame->pCommand, "command") == 0) {
//                     if (strcmp(pURL_Frame->pFilename, "info") == 0) {
//                     } else if (strcmp(pURL_Frame->pFilename, "status") == 0) {
//                     } else {
//                         response_send(ptrespconn, false);
//                     }
//              } 
                }break; //GET

            case PUT: {
                #ifdef DEBUG1
                os_printf("PUT/");
                os_printf("S: %s C: %s F: %s\n",pURL_Frame->pSelect,pURL_Frame->pCommand,pURL_Frame->pFilename);
                #endif
                pParseBuffer = (char *)strstr(precvbuffer, "\r\n\r\n");

                if (pParseBuffer == NULL) {
                    break;
                }

                pParseBuffer += 4;
                #ifdef DEBUG1
                os_printf("pParseB: ");
                for ( i=0; i<datlen ; i++ ) os_printf("%02x",pParseBuffer[i]);
                os_printf("\n");
                #endif

                if (strcmp(pURL_Frame->pSelect, "characteristics") == 0 && pcryp->encrypted) {
                    #ifdef DEBUG1
                    os_printf("characteristics\n");
                    #endif
                    parse_chas(pcryp, pParseBuffer);
                    h204_send(pcryp);
                }

                }break; //PUT
                
            case POST: {
                #ifdef DEBUG1
                os_printf("POST/");
                os_printf("S: %s C: %s F: %s\n",pURL_Frame->pSelect,pURL_Frame->pCommand,pURL_Frame->pFilename);
                #endif
                pParseBuffer = (char *)strstr(precvbuffer, "\r\n\r\n");

                if (pParseBuffer == NULL) {
                    break;
                }

                pParseBuffer += 4;
                #ifdef DEBUG1
                os_printf("pParseB: ");
                for ( i=0; i<datlen ; i++ ) os_printf("%02x",pParseBuffer[i]);
                os_printf("\n");
                #endif

                if (strcmp(pURL_Frame->pSelect, "identify") == 0) {
                    #ifdef DEBUG1
                    os_printf("POST identify not yet implemented\n");
                    #endif
                    //do identify routine as a task
                    h204_send(pcryp);
                }

                if (strcmp(pURL_Frame->pSelect, "pairings") == 0 && pcryp->encrypted) {
                    #ifdef DEBUG1
                    os_printf("pairings\n");
                    #endif
                    //parse tlv8
                    tlv8_parse(pParseBuffer,datlen,objects,objects_len); 
                    //based on 06 value switch to a routine in srpsteps.c which sends chunked tlv8 body
                    switch (objects[0][0]) {
                        case 0x03:
                            #ifdef DEBUG1
                            os_printf("Free heap1:%d\n", system_get_free_heap_size());
                            #endif
                            pcryp->state=7;
                            xQueueSendToFront(crypto_queue,&pcryp,0);
                            delegated=true;
                            #ifdef DEBUG1
                            os_printf("Free heap2:%d\n", system_get_free_heap_size());
                            #endif
                            break;
                        case 0x04:
                            #ifdef DEBUG1
                            os_printf("Free heap3:%d\n", system_get_free_heap_size());
                            #endif
                            pcryp->state=8;
                            xQueueSendToFront(crypto_queue,&pcryp,0);
                            delegated=true;
                            #ifdef DEBUG1
                            os_printf("Free heap4:%d\n", system_get_free_heap_size());
                            #endif
                            break;
                    }
                }

                if (strcmp(pURL_Frame->pSelect, "pair-setup") == 0 && pairing) { //only if not paired yet
                    #ifdef DEBUG1
                    os_printf("pair-setup\n");
                    #endif
                    //parse tlv8
                    tlv8_parse(pParseBuffer,datlen,objects,objects_len); 
                    //based on 06 value switch to a routine in srpsteps.c which sends chunked tlv8 body
                    switch (objects[6][0]) {
                        case 0x01:
                            #ifdef DEBUG1
                            os_printf("Free heap1:%d\n", system_get_free_heap_size());
                            #endif
                            crypto_setup1(pcryp);
                            #ifdef DEBUG1
                            os_printf("Free heap2:%d\n", system_get_free_heap_size());
                            #endif
                            break;
                        case 0x03:
                            #ifdef DEBUG1
                            os_printf("Free heap3:%d\n", system_get_free_heap_size());
                            #endif
                            pcryp->state=2;
                            xQueueSendToFront(crypto_queue,&pcryp,0);
                            delegated=true;
                            #ifdef DEBUG1
                            os_printf("Free heap4:%d\n", system_get_free_heap_size());
                            #endif
                            break;
                        case 0x05:
                            #ifdef DEBUG1
                            os_printf("Free heap5:%d\n", system_get_free_heap_size());
                            #endif
                            pcryp->state=3;
                            xQueueSendToFront(crypto_queue,&pcryp,0);
                            delegated=true;
                            #ifdef DEBUG1
                            os_printf("Free heap6:%d\n", system_get_free_heap_size());
                            #endif
                            break;
                    }
                }
                if (strcmp(pURL_Frame->pSelect, "pair-verify") == 0) {
                    #ifdef DEBUG1
                    os_printf("pair-verify\n");
                    #endif
                    //parse tlv8
                    tlv8_parse(pParseBuffer,datlen,objects,objects_len); 
                    //based on 06 value switch to a routine in srpsteps.c which sends chunked tlv8 body
                    switch (objects[6][0]) {
                        case 0x01:
                            #ifdef DEBUG1
                            os_printf("Free heap1:%d\n", system_get_free_heap_size());
                            #endif
                            pcryp->state=4;
                            xQueueSendToBack(crypto_queue,&pcryp,0);
                            delegated=true;
                            #ifdef DEBUG1
                            os_printf("Free heap2:%d\n", system_get_free_heap_size());
                            #endif
                            break;
                        case 0x03:
                            #ifdef DEBUG1
                            os_printf("Free heap3:%d\n", system_get_free_heap_size());
                            #endif
                            pcryp->state=5;
                            xQueueSendToFront(crypto_queue,&pcryp,0);
                            delegated=true;
                            #ifdef DEBUG1
                            os_printf("Free heap4:%d\n", system_get_free_heap_size());
                            #endif
                            break;
                    }
                }
//                 if (strcmp(pURL_Frame->pSelect, "config") == 0 && strcmp(pURL_Frame->pCommand, "command") == 0) {
//                     if (strcmp(pURL_Frame->pFilename, "reboot") == 0) {
//                     } else if (strcmp(pURL_Frame->pFilename, "wifi") == 0) {
//                     } else if (strcmp(pURL_Frame->pFilename, "switch") == 0) {
//                     /*    if (pParseBuffer != NULL) {
//                             struct jsontree_context js;
//                             jsontree_setup(&js, (struct jsontree_value *)&StatusTree, json_putchar);
//                             json_parse(&js, pParseBuffer);
//                             response_send(ptrespconn, true);
//                         } else {
//                             response_send(ptrespconn, false);
//                         } /**/
//                     } else {
//                         response_send(pcryp, false);
//                     }
//                 }
                }break; //POST
        }

        if (precvbuffer != NULL){
            free(precvbuffer);
            precvbuffer = NULL;
        }
        free(pURL_Frame);
        pURL_Frame = NULL;
        _temp_exit:
            ;
        
        if (!delegated) xSemaphoreGive(pcryp->semaphore);
    } else os_printf("-- received a packet and ignored because semaphore blocked (or pcryp==NULL)");
}

/******************************************************************************
 * FunctionName : server_sent
 * Description  : a packet has been sent
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL ICACHE_FLASH_ATTR
void server_sent(void *arg)
{
    struct espconn *pesp_conn = arg;

    #ifdef DEBUG0
    os_printf("server sent a packet to  %d.%d.%d.%d:%d at %d\n", pesp_conn->proto.tcp->remote_ip[0],
            pesp_conn->proto.tcp->remote_ip[1],pesp_conn->proto.tcp->remote_ip[2],
            pesp_conn->proto.tcp->remote_ip[3],pesp_conn->proto.tcp->remote_port,system_get_time()/1000);
    #endif
}

/******************************************************************************
 * FunctionName : server_cleanup
 * Description  : release memory of a finished connection
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL ICACHE_FLASH_ATTR
void server_cleanup(void *arg)
{
    crypto_parm *pcryp = arg;
    int iid;
    
    #ifdef DEBUG1
    os_printf("Cleaning %x @ %d CID: %d\n",pcryp,system_get_time()/1000,pcryp->connectionid);
    #endif
    pcryp->stale=1;
    for (iid=1;iid<MAXITM+1;iid++) acc_items[iid].events&=~pcryp->connectionid;; //clear all possible events of this connection
    while (xSemaphoreTake( pcryp->semaphore, ( portTickType ) 50 ) == pdFALSE ) {os_printf("Waiting  %x @ %d\n",pcryp,system_get_time()/1000);} //0.5 seconds
    #ifdef DEBUG1
    os_printf("Freeing  %x @ %d\n",pcryp,system_get_time()/1000);
    #endif
    vSemaphoreDelete( pcryp->semaphore );
    free(pcryp);
    vTaskDelete(NULL);
}

/******************************************************************************
 * FunctionName : server_recon
 * Description  : the connection has been err, reconnection
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL ICACHE_FLASH_ATTR
void server_recon(void *arg, sint8 err)
{
    struct espconn *pesp_conn = arg;

    #ifdef DEBUG0
    os_printf("client %d.%d.%d.%d:%d disconnected with status %d\n", pesp_conn->proto.tcp->remote_ip[0],
            pesp_conn->proto.tcp->remote_ip[1],pesp_conn->proto.tcp->remote_ip[2],
            pesp_conn->proto.tcp->remote_ip[3],pesp_conn->proto.tcp->remote_port, err);
    #endif
    if (pesp_conn->reserve != NULL){
        xTaskCreate(server_cleanup, "clean", 512, pesp_conn->reserve, 1, NULL);  //512 is enough?
        pesp_conn->reserve = NULL;
    }
}

/******************************************************************************
 * FunctionName : server_discon
 * Description  : the connection has been disconnected
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL ICACHE_FLASH_ATTR
void server_discon(void *arg)
{
    server_recon(arg,0);
}

/******************************************************************************
 * FunctionName : user_accept_listen
 * Description  : server listened a connection successfully
 * Parameters   : arg -- Additional argument to pass to the callback function
 * Returns      : none
*******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
server_listen(void *arg)
{
    espconn_msg *plist = NULL;
    plist = plink_active;
    struct espconn *pesp_conn = arg;
    crypto_parm *pcryp;
    crypto_parm *other;
    uint32_t keepalive;
    uint32_t active=0,myconnid=1;
    
    pcryp = (crypto_parm *)zalloc(sizeof(crypto_parm));
    vSemaphoreCreateBinary(pcryp->semaphore);
    #ifdef DEBUG0
    if ( xSemaphoreTake( pcryp->semaphore, ( portTickType ) 0 ) == pdTRUE ) os_printf("p_sema taken\n");
    #endif

    pesp_conn->reserve=pcryp;
    pcryp->pespconn  =pesp_conn;

    pcryp->stale    =0;
    pcryp->encrypted=0;
    pcryp->countwr  =0;
    pcryp->countrd  =0;
        
    // See if we can obtain the semaphore. If the semaphore is not available wait 10 ticks to see if it becomes free.
    if( xSemaphoreTake( cid_semaphore, ( portTickType ) 10 ) == pdTRUE ){ //100ms - We were able to obtain the semaphore and can now access the shared resource.
        //run through connection list and collect current connection numbers
        while(plist != NULL){
            if (other=plist->pespconn->reserve) active+=other->connectionid;
            plist = plist->pnext;
        }
        //os_printf("active:%08x  ",active);
        //find a free number in the collection
        while (active&1) {myconnid<<=1;active>>=1;}
        pcryp->connectionid=myconnid;
        xSemaphoreGive( cid_semaphore );// We have finished accessing the shared resource. Release the semaphore.
    } else {
        // We could not obtain the semaphore and can therefore not access the shared resource safely.
        // connectionid stays zero, which needs to result in no error but also no events
        #ifdef DEBUG0
        os_printf("noSemaphore\n");
        #endif
    }
    xSemaphoreGive( pcryp->semaphore ); //we are done manipulating pcryp things
    
    #ifdef DEBUG0
    os_printf("%x  connects  from %d.%d.%d.%d:%d id:%08x\n", arg, pesp_conn->proto.tcp->remote_ip[0],
                pesp_conn->proto.tcp->remote_ip[1],pesp_conn->proto.tcp->remote_ip[2],
                pesp_conn->proto.tcp->remote_ip[3],pesp_conn->proto.tcp->remote_port,myconnid);
    #endif

    espconn_regist_recvcb(pesp_conn, server_recv);
    espconn_regist_sentcb(pesp_conn, server_sent);
    espconn_regist_reconcb(pesp_conn, server_recon);
    espconn_regist_disconcb(pesp_conn, server_discon);
    espconn_set_opt(pesp_conn, ESPCONN_KEEPALIVE);
    keepalive=90;espconn_set_keepalive(pesp_conn,ESPCONN_KEEPIDLE, &keepalive);
    keepalive=10;espconn_set_keepalive(pesp_conn,ESPCONN_KEEPINTVL,&keepalive);
    keepalive= 6;espconn_set_keepalive(pesp_conn,ESPCONN_KEEPCNT,  &keepalive);
}

/******************************************************************************
 * FunctionName : server_init
 * Description  : parameter initialize as a server
 * Parameters   : port -- server port
 * Returns      : none
*******************************************************************************/
void ICACHE_FLASH_ATTR
server_init(uint32 port)
{
    LOCAL esp_tcp esptcp;

    // Create the semaphore to guard the connection number.
    if( cid_semaphore == NULL ) vSemaphoreCreateBinary( cid_semaphore );
    // Create the queue to handle cryptoTasks in sequence
    crypto_queue=xQueueCreate(12,sizeof( crypto_parm * ));
    xTaskCreate(crypto_tasks, "crypto_tasks", 2560, NULL, 1, NULL);

    hkcesp_conn.type = ESPCONN_TCP;
    hkcesp_conn.state = ESPCONN_NONE;
    hkcesp_conn.proto.tcp = &esptcp;
    hkcesp_conn.proto.tcp->local_port = port;
    espconn_regist_connectcb(&hkcesp_conn, server_listen);

    espconn_accept(&hkcesp_conn);
    #ifndef DEMO
    espconn_regist_time(&hkcesp_conn,7200,0); //better also use keepalive ?? 180->700seconds! 100->400s 7200->8h
    #endif
    espconn_browse(&hkcesp_conn);

    #ifdef DEBUG1
    os_printf("ServerInitPriority:%d\n", uxTaskPriorityGet( NULL ));
    #endif
}



/******************************************************************************
 * FunctionName : tlv8_parse
 * Description  : take incoming buffer and deliver tlv structure array
 * Parameters   : pbuf -- pointer to buffer
 *                len -- the length of the buffer
 *                objects -- the pointer to the struct array
*                 objects_len -- array of lengths of the struct
 * Returns      :
*******************************************************************************/
void ICACHE_FLASH_ATTR
tlv8_parse(char *pbuf, uint16 len, char *objects[], int objects_len[])
{
    int i,j,t,l;

    for ( i=0; i<TLVNUM ; i++)  objects_len[i]=0; //reset any old values
    
    for ( j=0; j<len ; )    {
        t=pbuf[j++]; //type
        #ifdef DEBUG3
        os_printf("t:%d-",t);
        #endif
        //verify validness of type
        i=objects_len[t]; //old length is insertionpoint
        objects_len[t]+=pbuf[j++]; //new length
        #ifdef DEBUG3
        os_printf("n:%d\n",objects_len[t]);
        #endif
        for ( l=0; l<(objects_len[t]-i) ; l++ ) {
            objects[t][i+l]=pbuf[j++];
        }
    }
    
    #ifdef DEBUG3
    for ( i=0; i<TLVNUM ; i++)    {
        if ( objects_len[i] ) {
            os_printf("%d:",i);
            for ( j=0 ; j<objects_len[i] ; j++ ) os_printf("%02x",objects[i][j]);
            os_printf("\n");
        }
    }
    #endif
}

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
void ICACHE_FLASH_ATTR
tlv8_add(char *pbuf, uint16 *index, int type, uint16 len, char *value)
{
    uint16 length=0;  //encoded size for chunk size
    uint16 done=0;    //part already transferred
    char *pindex;
    char chunksize[6]; //to prevent trailing 0 to overwrite first type
    
    pindex=pbuf + *index;
    #ifdef DEBUG3
    os_printf("i=%d,t=%d,l=%d\n",*index,type,len);
    #endif
    if (len < 14) {
        length=len+2; //t + l =2
        sprintf(pindex, "%x\r\n",length); //one digit
        length+=+3; //chunksize text
        *(pindex+3)=(char)type;
        *(pindex+4)=(char)len;
        memcpy(pindex+5,value,len);
    } else if (len < 254) {
        length=len+2; //t + l =2
        sprintf(pindex, "%x\r\n",length); //now two digits
        length+=+4; //chunksize text
        *(pindex+4)=(char)type;
        *(pindex+5)=(char)len;
        memcpy(pindex+6,value,len);
    } else {  //>253
        while (len> 255) {
            *(pindex+5)=(char)type;
            *(pindex+6)=(char)255;
            memcpy(pindex+7,value+done,255);
            len-=255; done+=255; length+=257; pindex+=257;
        }
        length+=len+2; //t + l =2
        sprintf(chunksize, "%x\r\n",length); //now three digits with trailing zero
        memcpy(pbuf + *index,chunksize,5);
        length+=+5; //chunksize text
        *(pindex+5)=(char)type;
        *(pindex+6)=(char)len;
        memcpy(pindex+7,value+done,len);
    }
    *index+=length;
    memcpy(pbuf + *index,"\r\n",2);
    *index+=2;
}

/******************************************************************************
 * FunctionName : tlv8_close
 * Description  : add the final chunked close item of zero length
 * Parameters   : pbuf -- pointer to buffer
 *                index -- distance to buffer insertion point will be updated
 * Returns      :
*******************************************************************************/
void ICACHE_FLASH_ATTR
tlv8_close(char *pbuf, uint16 *index)
{
    memcpy(pbuf + *index,"0\r\n\r\n",5);
    *index+=5;
}

 /******************************************************************************
      * FunctionName : parse_mdns
      * Description  : returns which type of question needs to be answered relevant to us
      * Parameters   : buf -- data in
      * Returns      : int bitmap: 0=not, +1=PTR, +2=TXT, (3=PTRTXT), +4=QU
 *******************************************************************************/

int parse_mdns(char* buf, unsigned short len) {

    unsigned int     i,j,n,ref,tag;
    //char    tag;
    char    name[256];
    
    #define GETNAME /* START OF MACRO FUNCTION GETNAME */ \
    j=i; tag=buf[j]; n=0; ref=0; \
    while (tag) { /*if tag==0 then end of name */ \
        if (tag>=0xc0) { /*referring*/ \
            ref++;j=256*(tag-0xc0)+buf[j+1]; \
            if (ref==1) i+=2; \
        } else { \
            if (tag>0x40 || j+1+tag>len || n+tag>253) {os_printf("mdns-error t=%d i=%d j=%d n=%d\n",tag,i,j,n);return 0;} /*label longer 64 or pointing out of buf */ \
            memcpy(name+n,buf+j+1,tag); \
            n+=tag; \
            name[n++]=0x2e; /*full stop . */ \
            j+=tag+1; \
            if (!ref) i+=tag+1; \
        } \
        tag=buf[j]; \
    } \
    name[n]=0; /*close string */ \
    if (!ref) i++ /*count the closing zero if never referred*/ \
    /* END OF MACRO FUNCTION GETNAME, no closing ; */

    int     q,a,result=0;
    char    hap[]="_hap._tcp.local.";
    char    fqdn[ANLMAX+18]; //make these global?
    
    strcpy(fqdn,myACCname);
    strcat(fqdn,".");
    strcat(fqdn,hap);
    #ifdef DEBUG5
    os_printf("FQDN: %s\n",fqdn);
    #endif

    for (i=0; i<5; i++) if (buf[i]) return 0; //is a request with id=0 and no other flags and less than 256 questions
    q=buf[i]; //number of questions
    a=buf[i+2]; //number of answers
    i=0x0c;   //start of name area
    while (q) {
        GETNAME;
        #ifdef DEBUG5
        os_printf("Q: %s\n",name);
        #endif
        //is this a question for us?
        if (!strcmp(name,hap)  && buf[i+1]==12) { //HAP PTR
            #ifdef DEBUG0
            os_printf("--- Q _hapPTR\n");
            #endif
            result|=1;
            if (buf[i+2]==0x80) result|=4; //QU
        }
        if (!strcmp(name,fqdn) && buf[i+1]==16) { //FQDN TXT
            #ifdef DEBUG0
            os_printf("--- Q nameTXT\n");
            #endif
            result|=2;
            if (buf[i+2]==0x80) result|=4; //QU
        }
        i+=4; //flush type, Class and QM
        q--; //next question
    }
    if (result) {
        while (a) {
            GETNAME;
            #ifdef DEBUG5
            os_printf("A: %s\n",name);
            #endif
            //is this our answer?
            if (!strcmp(name,hap)  && buf[i+1]==12) { //HAP PTR
                #ifdef DEBUG0
                os_printf("--- A _hapPTR\n");
                #endif
                i+=10; //flush type, Class, flush, ttl and len
                GETNAME;
                #ifdef DEBUG5
                os_printf("P: %s\n",name);
                #endif
                if (!strcmp(name,fqdn)) { //FQDN
                    #ifdef DEBUG0
                    os_printf("--- P name\n");
                    #endif
                    result&=~5; //suppresses the answer and QU flag
                }
            } else { //another answer
                i+=8; //flush type, Class, flush, and ttl
                i+=2+buf[i]*256+buf[i+1]; //flush len and content
            }
            a--; //next answer
        }
    }
    return result;
}

 /******************************************************************************
      * FunctionName : user_udp_recv
      * Description  : udp received callback
      * Parameters   : arg -- data in
      * Returns      : none
 *******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
user_udp_recv(void *arg, char *pusrdata, unsigned short length)
{
    struct espconn* udpconn = arg;
    remot_info      *premot = NULL;
    int         unicast_nok = 0;
    const char udp_mdns_ip[4] = {224, 0, 0, 251};  
    struct ip_info ipconfig;
    int             result;
    

    if  (espconn_get_connection_info(udpconn,&premot,0) == ESPCONN_OK){
        #ifdef DEBUG5
        os_printf("-- received from %d.%d.%d.%d:%d ", premot->remote_ip[0], premot->remote_ip[1], premot->remote_ip[2], premot->remote_ip[3], premot->remote_port);
        #endif
    }
    else{
        unicast_nok=1;
        #ifdef DEBUG0
        os_printf("Get mdns sender info failed\n");
        #endif
    }

    #ifdef DEBUG5
    //if (!pusrdata[2]) {
        os_printf(", len %d, heap %d, system time=%d\n", length, system_get_free_heap_size(),system_get_time()/1000);
        //int i; for (i=0;i<length;i++) os_printf("%02x",pusrdata[i]); os_printf("\n");
    //}
    #endif
    result=parse_mdns(pusrdata, length);
    if (result) {
        #ifdef DEBUG0
        os_printf("result: %d\n",result);
        #endif
        if (unicast_nok) result&=~4;
    
        wifi_get_ip_info(STATION_IF, &ipconfig);
        //os_printf("answerip:" IPSTR "\n",IP2STR(&ipconfig.ip.addr));
        memcpy(164+mdns+2*anl,&ipconfig.ip.addr,4);
        mdns[110+2*anl]=0x30+pairing;
        switch (result) {
            case 5: case 7: //unicast
            memcpy(user_udp_espconn.proto.udp->remote_ip, premot->remote_ip, 4); //unicast pending to do
            break;                                                         //how to get senders IP??
            default:
            memcpy(user_udp_espconn.proto.udp->remote_ip, udp_mdns_ip, 4); //multicast
            break;
        }
        user_udp_espconn.proto.udp->remote_port = 5353;    // ESP8266 udp remote port need to be set every time
        switch (result) {
            case 1: case 5: //PTR only
                mdns[7]=1; mdns[11]=3; //set 1 answer and 3 additionals
            break;
            case 3: case 7: //PTR and TXT
                mdns[7]=2; mdns[11]=2; //set 2 answers and 2 additionals
            break;
            default:
                return; //don't send anything
            break;
        }
        espconn_send(&user_udp_espconn, mdns, mdns_len-37);//cut of the services._dns-sd._udp.local
        mdns[7]=5; mdns[11]=0; //restore 5 answers and 0 additionals for recurring task
    }
}

 /******************************************************************************
      * FunctionName : user_udp_sent_cb
      * Description  : udp sent successfully
      * Parameters   : arg -- Additional argument to pass to the callback function
      * Returns      : none
 *******************************************************************************/
LOCAL void ICACHE_FLASH_ATTR
user_udp_sent(void *arg)
{  
    #ifdef DEBUG0
    os_printf("mdns sent: pairing %d, heap %d, time=%d\n", pairing, system_get_free_heap_size(),system_get_time()/1000);
    #endif
}

 /******************************************************************************
      * FunctionName : send_initial_mdns
      * Description  : send 5 answers when starting or changed circumstances
      * Parameters   : none
      * Returns      : none
 *******************************************************************************/
void send_initial_mdns()
{
    const char udp_mdns_ip[4] = {224, 0, 0, 251};  
    struct ip_info ipconfig;

    wifi_get_ip_info(STATION_IF, &ipconfig);
    //os_printf("initialmdnsip:" IPSTR "\n",IP2STR(&ipconfig.ip.addr));
    memcpy(164+mdns+2*anl,&ipconfig.ip.addr,4);
      mdns[110+2*anl]=0x30+pairing;
    memcpy(user_udp_espconn.proto.udp->remote_ip, udp_mdns_ip, 4); // ESP8266 udp remote IP need to be set everytime we call espconn_sent
    user_udp_espconn.proto.udp->remote_port = 5353;  // ESP8266 udp remote port need to be set everytime we call espconn_sent
    espconn_send(&user_udp_espconn, mdns, mdns_len);    
}

 /******************************************************************************
      * FunctionName : new_ip  IS A TASK that finishes itself
      * Description  : send initial mdns in exponential backoff scheme
      * Parameters   : arg  (not used)
      * Returns      : none
 *******************************************************************************/
void new_ip(void *arg)
{
    send_initial_mdns();
    vTaskDelay(100); //1sec
    send_initial_mdns();
    vTaskDelay(200); //2sec
    send_initial_mdns();
    vTaskDelay(400); //4sec
    send_initial_mdns();
    vTaskDelete(NULL);
}

 /******************************************************************************
      * FunctionName : wifi_handle_event_cb
      * Description  : detects wifi changes and orders a new_ip task
      * Parameters   : evt
      * Returns      : none
 *******************************************************************************/
void wifi_handle_event_cb(System_Event_t *evt)
{
    switch (evt->event_id) {
        case EVENT_STAMODE_DISCONNECTED:
            os_printf("disconnect from ssid %s, reason %d\n",
                        evt->event_info.disconnected.ssid,
                        evt->event_info.disconnected.reason);
        break;
        case EVENT_STAMODE_GOT_IP:
            xTaskCreate(new_ip,"newip",256,NULL,1,NULL);
        break;
        default:
        break;
    }
}

 /******************************************************************************
      * FunctionName : ip_init IS A TASK that continues forever
      * Description  : sets up IP related bussiness and mdns repeater
      * Parameters   : arg  is the accname
      * Returns      : none
 *******************************************************************************/
void ip_init(void *arg)
{
    struct ip_info ipconfig;
    const char udp_mdns_ip[4] = {224,   0,   0, 251};
    const char udp_null_ip[4] = {  0,   0,   0,   0};
    char *accname = arg;

    if (strlen(accname)<ANLMAX) anl=strlen(accname);
      mdns_len = 2*anl+205;
      mdns[ 38]=anl+3;
      mdns[ 39]=anl;
    memcpy( 40+mdns,accname,anl);
    memcpy( 40+mdns+anl,40+ANLMAX+mdns,205+2*ANLMAX-anl-40);//transfer other bytes forward
      mdns[ 53+anl]=anl+57;
      mdns[ 54+anl]=anl+3;
    memcpy( 58+mdns+anl,accname,anl);
    memcpy( 58+mdns+2*anl,58+ANLMAX+anl+mdns,205+ANLMAX-anl-58);//transfer other bytes forward
    memcpy( 69+mdns+2*anl,myUsername,17);
//    mdns[105+2*ANLMAX]=0x30+acc_category;  //set ci=... we do this before adjusting mdns
//    mdns[110+2*anl]=0x30+pairing;
    memcpy(133+mdns+2*anl,myUsername,17);
      mdns[153+2*anl]=2*anl+129;
//  memcpy(164+mdns+2*anl,&ipconfig.ip.addr,4);

    user_udp_espconn.type = ESPCONN_UDP;
    user_udp_espconn.proto.udp = (esp_udp *)zalloc(sizeof(esp_udp));
    user_udp_espconn.proto.udp->local_port = 5353;  // set mdns  port

    while (!ready)vTaskDelay(5); //50ms

    do {vTaskDelay(5);
        wifi_get_ip_info(STATION_IF, &ipconfig);
        //os_printf("noip: " IPSTR "\n",IP2STR(&ipconfig.ip.addr));
    } while (!ip4_addr1(&ipconfig.ip.addr) && !ip4_addr2(&ipconfig.ip.addr) && !ip4_addr3(&ipconfig.ip.addr) && !ip4_addr4(&ipconfig.ip.addr));

    wifi_set_event_handler_cb(wifi_handle_event_cb);
    
    server_init(0x0295); // iana HAP port 661

    espconn_igmp_join((ip_addr_t*)udp_null_ip, (ip_addr_t*)udp_mdns_ip);  //using own IP is crash
    espconn_regist_recvcb(&user_udp_espconn, user_udp_recv);
    espconn_regist_sentcb(&user_udp_espconn, user_udp_sent); // register a udp packet sent callback
    espconn_create(&user_udp_espconn);   // create udp socket

    xTaskCreate(new_ip,"newip",256,NULL,1,NULL);
    while(1) {
        vTaskDelay(360000); //3600 sec
        do {vTaskDelay(5);
            wifi_get_ip_info(STATION_IF, &ipconfig);
            //os_printf("ip:" IPSTR "\n",IP2STR(&ipconfig.ip.addr));
        } while (!ip4_addr1(&ipconfig.ip.addr) && !ip4_addr2(&ipconfig.ip.addr) && !ip4_addr3(&ipconfig.ip.addr) && !ip4_addr4(&ipconfig.ip.addr));
        send_initial_mdns();
        vTaskDelay(100); //1sec
        send_initial_mdns();
        vTaskDelay(200); //2sec
        send_initial_mdns();
    }
}

/***********************************************************************/

//HacK the function as chosen by Apple is just the hash of the secret
int wc_SrpSetKeyH(Srp* srp, byte* secret, word32 size) //can this be static???
{
    SrpHash hash;
    int r = BAD_FUNC_ARG;

    srp->key = (byte*)XMALLOC(SHA512_DIGEST_SIZE, NULL, DYNAMIC_TYPE_SRP);
    if (srp->key == NULL)
        return MEMORY_E;

    srp->keySz = SHA512_DIGEST_SIZE;

    r = wc_InitSha512(&hash.data.sha512);
    if (!r) r = wc_Sha512Update(&hash.data.sha512, secret, size);
    if (!r) r = wc_Sha512Final(&hash.data.sha512, srp->key);

    //ForceZero(&hash, sizeof(SrpHash));
    memset(&hash,0,sizeof(SrpHash));

    return r;
}

static void srp_prepare()
{
    int r;
    byte g[]={0x05};
    word32 g_len=1;
    byte salt[16];
    word32 salt_len=16;
    byte    b[32];
    word32  b_len=32;   

    #ifdef DEBUG2
    os_printf("system time: %d\n",system_get_time()/1000);
    #endif
            r = os_get_random((unsigned char *)salt, salt_len);
            r = os_get_random((unsigned char *)b, b_len);
    #ifdef DEBUG2
    os_printf("s: "); for (r=0;r<salt_len;r++)os_printf("%02x",salt[r]); os_printf("\n");
    os_printf("b: "); for (r=0;r<b_len;r++)os_printf("%02x",b[r]); os_printf("\n");
    #endif
            r = wc_SrpInit(&srp, SRP_TYPE_SHA512, SRP_CLIENT_SIDE);
            srp.keyGenFunc_cb = wc_SrpSetKeyH;
    if (!r) r = wc_SrpSetUsername(&srp, "Pair-Setup", 10);
    if (!r) r = wc_SrpSetParams(&srp, B, NLEN, g, g_len, salt, salt_len);
    if (!r) r = wc_SrpSetPassword(&srp, PASSWORD, PASSWORD_LEN);
    if (!r) r = wc_SrpGetVerifier(&srp, B, &B_len); //use B to store v
    srp.side=SRP_SERVER_SIDE; //switch to server mode
    if (!r) r = wc_SrpSetVerifier(&srp, B, B_len); //used B to store v
    if (!r) r = wc_SrpSetPrivate(&srp, b, b_len);
    if (!r) r = wc_SrpGetPublic(&srp, B, &B_len);
    //print stack high water mark
    //vTaskList(report);
    //os_printf("%s",report);
    #ifdef DEBUG2
    os_printf("srp_prepare done: system time: %d\n",system_get_time()/1000);
    os_printf("B: ");
    for (r=0; r<NLEN ; r++) os_printf("%02x",B[r]);
    os_printf("\n");
    #endif
    ready=1; //this unlocks the mdns messages and server
    vTaskDelete(NULL);
}

void crypto_init()
{
    //if already stored then retrieve, else generate and store
    //also for myUsername
    char    flash[80];
    char    signature[20] = "HomeACcessoryKid"; //keep it 32bit aligned
    char    signawipe[20] = "XXXXXXXXXXXXXXXX"; //keep it 32bit aligned
    WC_RNG  rng;
    int     makekey=1;
    int     r;
    
    spi_flash_read(START+4080,(uint32 *)flash,16);flash[16]=0;
    #ifdef DEBUG0
    for (r=0;r<17;r++) os_printf("%02x",flash[r]);os_printf("\n");
    #endif
    if (strcmp(flash,signature)) {
        spi_flash_read(0x13*0x1000+4080,(uint32 *)flash,16);flash[16]=0; //former location of user data
        #ifdef DEBUG0
        for (r=0;r<17;r++) os_printf("%02X",flash[r]);os_printf("\n");
        #endif
        if (strcmp(flash,signature)) {
            #ifdef DEBUG0
            os_printf("initializing flash in 5 seconds\n");
            vTaskDelay(500);
            os_printf("initializing flash at %X\n",START+4080);
            #endif
            spi_flash_erase_sector(SECTOR);
            spi_flash_write(START+4080,(uint32 *)signature,16);
        } else { //transplant 0x13 to SECTOR
            #ifdef DEBUG0
            os_printf("transplanting flash in 5 seconds\n");
            vTaskDelay(500);
            os_printf("transplanting flash to %X\n",START);
            #endif
            spi_flash_erase_sector(SECTOR);
            for (r=0;r<256;r++) {
                spi_flash_read(0x13*0x1000+r*16,(uint32 *)flash,16);
                spi_flash_write(     START+r*16,(uint32 *)flash,16);
            }
            spi_flash_write(0x13*0x1000+4080,(uint32 *)signawipe,16);
        }
    }   
    spi_flash_read(START+4000,(uint32 *)flash,64);
    #ifdef DEBUG0
    for (r=0;r<64;r++) os_printf("%02x",flash[r]);os_printf("\n");
    #endif
    for (r=0;r<64;r++) if (flash[r]!=0xff) makekey=0;
    
                r = wc_ed25519_init(&myKey);
    if (!r && makekey) {
        r = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &myKey);
        makekey=ED25519_PRV_KEY_SIZE; //write to flash, abuse existing int
        if (!r) r = wc_ed25519_export_private(&myKey, flash, &makekey);
        if (!r) r = spi_flash_write(START+4000,(uint32 *)flash,64);
        #ifdef DEBUG0
        os_printf("key written: %d\n",r);
        #endif
        spi_flash_read(START+4000,(uint32 *)flash,64);
        #ifdef DEBUG0   
        for (r=0;r<64;r++) os_printf("%02x",flash[r]);os_printf("\n");
        #endif
        
        //make random username as a 6 byte field
        char mac[6];
        os_get_random((unsigned char *)mac, 6);
        sprintf(myUsername,"%02X:%02X:%02X:%02X:%02X:%02X",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
        myUsername[8]=myUsername[16]; //store last digit in the middle to store
        spi_flash_write(START+4064,(uint32 *)myUsername,16);
        myUsername[8]=0x3a; //restore the middle colon
        #ifdef DEBUG0
        os_printf("username written: "); //do not save the middle ':' we only have 16 positions, not 17
        #endif
        spi_flash_read(START+4064,(uint32 *)flash,16);flash[16]=0;
        #ifdef DEBUG0   
        printf("%s\n",flash);
        #endif
    } else {
        if (!r) r = wc_ed25519_import_private_key(flash,ED25519_KEY_SIZE,flash+ED25519_KEY_SIZE,ED25519_PUB_KEY_SIZE,&myKey);
        #ifdef DEBUG0
        os_printf("key loaded:  %d\n",r);
        #endif
        spi_flash_read(START+4064,(uint32 *)myUsername,16);
        myUsername[16]=myUsername[8];
        myUsername[8]=0x3a;
        myUsername[17]=0x0;
    }
    #ifdef DEBUG0
    os_printf("myUsername: %s\n",myUsername);
    #endif
    //if an ID stored at position 0 then we are paired already so no need to set up pairing procedures
    //each record is 80 bytes, 12 flag, 36 username, 32 clientPubKey
    pairing=1;
    spi_flash_read(START,(uint32 *)flash,80);
    if (flash[0]==0x7f) halfpaired=1;
    for (r=1;r<12;r++) if (flash[r]!=0xff) pairing=0;
    #ifdef DEBUG0   
    os_printf("pairing: %d\n",pairing);
    for (r=0;r<80;r++) os_printf("%02x",flash[r]);os_printf("\n");
    #endif
}

void hkc_init(char *accname, ...)
{
    char mac[6];
    va_list ap;
    int acc_category;
    
    #ifdef DEBUG0   
    os_printf("hkc by HomeACcessoryKid! Compiled %s@%s Heap: %d\n", __DATE__, __TIME__, system_get_free_heap_size());
    #endif
    
    va_start(ap,accname);
    acc_category=va_arg(ap,int);
    va_end(ap);
    acc_category=(acc_category>9)?1:acc_category; //while we have a simple mdns structure, max 1 digit
    os_printf("Accessory_Category: %d\n",acc_category);
    mdns[105+2*ANLMAX]=0x30+acc_category;  //set ci=... we do this before adjusting mdns
    strncpy(myACCname,accname,ANLMAX-2); //cut off extra
    wifi_get_macaddr(STATION_IF, mac);
    sprintf(myACCname+strlen(myACCname),"%02X",mac[5]);//append the last two characters of mac address
    //strcat(myACCname,myUsername+15); //append the last two characters of Username
    os_printf("myACCname: %s\n",myACCname);

    espconn_init();
    crypto_init();
    if (pairing)    xTaskCreate(srp_prepare, "prep", 2560, NULL, 1, NULL);
    else            xTaskCreate(  json_init,"jinit", 2560, NULL, 1, NULL);
    xTaskCreate(ip_init,"ip",256,myACCname,1,NULL);
}

void crypto_tasks()  //this is a TasK
{
    crypto_parm *pcryp=NULL;
    while(1) {
        //get queue item
        os_printf("waiting for task\n");
        xQueueReceive(crypto_queue, &pcryp, portMAX_DELAY);
        //execute the right routine if not stale
        if (!pcryp->stale) {
            switch (pcryp->state) { //make an enum
    //          case 1: {
    //              crypto_setup1(pcryp);
    //             }break; //1
                case 2: {
                    crypto_setup3(pcryp);
                }break; //2
                case 3: {
                    crypto_setup5(pcryp);
                }break; //3
                case 4: {
                    crypto_verify1(pcryp);
                    //delay X0ms so follow up packet can jump the head of the queue
                    //vTaskDelay(4); //this has likely provoked a lot of trouble prior to 28/10/2017
                }break; //4
                case 5: {
                    crypto_verify3(pcryp);
                    //delay Y0ms so follow up packet can jump the head of the queue
                    //vTaskDelay(5); //this has likely provoked a lot of trouble prior to 28/10/2017
                }break; //5
                case 6: {
                    acc_send(pcryp);
                }break; //6
                case 7: {
                    pairadd(pcryp);
                }break; //7
                case 8: {
                    pairdel(pcryp);
                }break; //8
            }
        }
        //release semaphore
        xSemaphoreGive(pcryp->semaphore);
    }
}

void crypto_setup1(void *arg)
{
    crypto_parm *pcryp = arg;
    char *ptlv8body = NULL;
    uint16 index;
    int r;
    byte salt[16];
    word32 salt_len=16;

    ptlv8body=(char *)zalloc(432); index=0;
    memcpy(salt,srp.salt,salt_len);
    #ifdef DEBUG2
    os_printf("srp pair step 1! Free heap:%d\n", system_get_free_heap_size());
    os_printf("s: "); for (r=0;r<salt_len;r++)os_printf("%02x",salt[r]); os_printf("\n");
    #endif
    tlv8_add(ptlv8body,&index,6,1,two);
    tlv8_add(ptlv8body,&index,2,salt_len,salt);
    tlv8_add(ptlv8body,&index,3,B_len,B);
    tlv8_close(ptlv8body,&index);
    #ifdef DEBUG2
    os_printf("chunked_len: %d\n",index);
    os_printf("Priority:%d\n", uxTaskPriorityGet( NULL ));
    #endif
    tlv8_send(pcryp, ptlv8body, index);
    //now ptlvbody cleaned in tlv8_send but consider doing that here
}

void crypto_setup3(void *arg)
{
    crypto_parm *pcryp = arg;
    int  *objects_len=pcryp->objects_len;
    char *objects[TLVNUM]= {pcryp->object+0x1c0,//0
                            pcryp->object+0x60, //1
                            NULL,
                            pcryp->object,      //3
                            pcryp->object+0x180,//4
                            pcryp->object+0xb0, //5
                            pcryp->object+0x1c1,//6
                            NULL,
                            NULL,
                            NULL,
                            pcryp->object+0x20, //10
                            pcryp->object+0x1c2 //11
    };
    byte proof[SHA512_DIGEST_SIZE];
    word32  proof_len=SHA512_DIGEST_SIZE;
    char *ptlv8body = NULL;
    uint16 index;
    
    ptlv8body=(char *)zalloc(85); index=0;
    #ifdef DEBUG2
    os_printf("srp pair step 3!\r\n");
    os_printf("Free heap:%d\n", system_get_free_heap_size());
    #endif

    int r;
            r = wc_SrpComputeKey(&srp, objects[3], objects_len[3], B, B_len);
    //os_printf("Ckey: %d\n",r);
    
    if (!r) r = wc_SrpVerifyPeersProof(&srp, objects[4], objects_len[4]);
    //os_printf("VPPr: %d\n",r);
    if (!r) r = wc_SrpGetProof(&srp, proof, &proof_len);
    //os_printf("Gprf: %d\n",r);
    #ifdef DEBUG2
    os_printf("key: ");
    for (r=0; r<srp.keySz ; r++) os_printf("%02x",srp.key[r]);
    os_printf("\n");
    #endif
    tlv8_add(ptlv8body,&index,6,1,four);
    tlv8_add(ptlv8body,&index,4,proof_len,proof);
    tlv8_close(ptlv8body,&index);
    #ifdef DEBUG2
    os_printf("chunked_len: %d\n",index);
    #endif
    tlv8_send(pcryp, ptlv8body, index);
    //now ptlvbody cleaned in tlv8_send but consider doing that here
}

void crypto_setup5(void *arg)
{
    crypto_parm *pcryp = arg;
    int  *objects_len=pcryp->objects_len;
    char *objects[TLVNUM]= {pcryp->object+0x1c0,//0
                            pcryp->object+0x60, //1
                            NULL,
                            pcryp->object,      //3
                            pcryp->object+0x180,//4
                            pcryp->object+0xb0, //5
                            pcryp->object+0x1c1,//6
                            NULL,
                            NULL,
                            NULL,
                            pcryp->object+0x20, //10
                            pcryp->object+0x1c2 //11
    };
    ed25519_key     clKey;
    byte encKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    byte conKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    byte accKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    byte esalt[] = "Pair-Setup-Encrypt-Salt";
    word32  esaltSz=23;
    byte einfo[] = "Pair-Setup-Encrypt-Info";
    word32  einfoSz=23;
    byte csalt[] = "Pair-Setup-Controller-Sign-Salt";
    word32  csaltSz=31;
    byte cinfo[] = "Pair-Setup-Controller-Sign-Info";
    word32  cinfoSz=31;
    byte asalt[] = "Pair-Setup-Accessory-Sign-Salt";
    word32  asaltSz=30;
    byte ainfo[] = "Pair-Setup-Accessory-Sign-Info";
    word32  ainfoSz=30;

    char    flash[80];
    
    char *ptlv8body = NULL;
    uint16 index;
    int verified;
    byte nonce[]= "0000PS-Msg05"; //needs to be 12 bytes, will prepad with 0000s
    
    nonce[0]=0; nonce[1]=0;nonce[2]=0;nonce[3]=0; //padding the first four bytes
    ptlv8body=(char *)zalloc(180); index=0;  //tune size
    #ifdef DEBUG2
    os_printf("srp pair step 5!\r\n");
    os_printf("Free heap:%d\n", system_get_free_heap_size());
    #endif
    
    int r;
            r = wc_HKDF(SHA512, srp.key, srp.keySz, esalt, esaltSz, einfo, einfoSz,
                        encKey, CHACHA20_POLY1305_AEAD_KEYSIZE);
    #ifdef DEBUG2
    os_printf("encKey%d:",r);
    for (r=0; r< CHACHA20_POLY1305_AEAD_KEYSIZE ; r++) os_printf("%02x",encKey[r]);
    os_printf("\n");
    #endif
    r=0;
    if (!r) r = wc_ChaCha20Poly1305_Decrypt(encKey, nonce, NULL, 0, 
                objects[5], objects_len[5]-16, objects[5]+objects_len[5]-16, ptlv8body);
    if (!r) tlv8_parse(ptlv8body,objects_len[5]-16,objects,objects_len); 
    
    /*******************************************************************/
    
    byte    myLTPK[ED25519_PUB_KEY_SIZE];
    word32  myLTPK_len=ED25519_PUB_KEY_SIZE;
    r = wc_ed25519_export_public(&myKey, myLTPK, &myLTPK_len);
    #ifdef DEBUG2
    os_printf("myLTPK: "); for (r=0;r<myLTPK_len;r++) os_printf("%02x",myLTPK[r]); os_printf("\n");
    #endif
    //clientLTPK key should be imported for usage
            r = wc_ed25519_init(&clKey);
            r = wc_ed25519_import_public(objects[3], objects_len[3], &clKey);
    
    /****** verify clients ed25519 signature  ***************************/
    r = wc_HKDF(SHA512, srp.key, srp.keySz, csalt, csaltSz, cinfo, cinfoSz, conKey, 32);
    //concat conKey, objects[1], objects[3]  and (ab)use objects[5] for storage
    memcpy(objects[5]               ,conKey    ,32            ); objects_len[5]=32;
    memcpy(objects[5]+objects_len[5],objects[1],objects_len[1]); objects_len[5]+=objects_len[1];
    memcpy(objects[5]+objects_len[5],objects[3],objects_len[3]); objects_len[5]+=objects_len[3];
    
    //ed25519.Verify(concat, clientProof[10], clientLTPK[3])
    r = wc_ed25519_verify_msg(objects[10], objects_len[10], objects[5],objects_len[5], &verified, &clKey);
    #ifdef DEBUG0
    os_printf("verified=%d r=%d\n",verified,r);
    #endif
    //stop mDNS advertising and store that decision?
    
    if (verified && !halfpaired) { //prevent double writing
        #ifdef DEBUG2
        spi_flash_read(START,(uint32 *)flash,80);
        for (r=0;r<80;r++) os_printf("%02x",flash[r]);os_printf("\n");
        #endif
        flash[0]=0x7f;
        memset(flash+1,0xff,11); //flag first 12 bytes to 01111111111...1111
        memcpy(flash+12,               objects[1],objects_len[1]); //client userName
        memcpy(flash+12+objects_len[1],objects[3],objects_len[3]); //clientLTPK
        #ifdef DEBUG0
        os_printf("writing paired client to flash\n");
        #endif
        spi_flash_write(START,(uint32 *)flash,80);
        halfpaired=1;
        #ifdef DEBUG2
        spi_flash_read(START,(uint32 *)flash,80);
        for (r=0;r<80;r++) os_printf("%02x",flash[r]);os_printf("\n");
        #endif
    }
    // else send 7/1/2
    /******** sign my own part ********************************************/
    r = wc_HKDF(SHA512, srp.key, srp.keySz, asalt, asaltSz, ainfo, ainfoSz, accKey, 32);
    //concat accKey, myUserName, myLTPK  and (ab)use objects[5] for storage
    memcpy(objects[5]               ,accKey    ,32            ); objects_len[5]=32;
    memcpy(objects[5]+objects_len[5],myUsername,myUsername_len); objects_len[5]+=myUsername_len;
    memcpy(objects[5]+objects_len[5],myLTPK    ,myLTPK_len    ); objects_len[5]+=myLTPK_len    ;
    //sign this and use objects[10] for proof storage
    objects_len[10]=objects_maxlen[10];
    r = wc_ed25519_sign_msg(objects[5], objects_len[5], objects[10], &objects_len[10], &myKey);
    //fill ptlv8body again with concatenated items 1, 3 and 10 in tlv8 style
    index=0; ptlv8body[index++]=1;   ptlv8body[index++]=myUsername_len;
    for (r=0; r<myUsername_len;r++)  ptlv8body[index++]=myUsername[r];
    ptlv8body[index++]=3;            ptlv8body[index++]=myLTPK_len;
    for (r=0; r<myLTPK_len;r++)      ptlv8body[index++]=myLTPK[r];
    ptlv8body[index++]=10;           ptlv8body[index++]=objects_len[10];
    for (r=0; r<objects_len[10];r++) ptlv8body[index++]=objects[10][r];
    // encrypt this and (ab)use objects[5] for storage
    nonce[11]=0x36; //turn it into "0000PS-Msg06"
    objects_len[5]=index+16;
    r = wc_ChaCha20Poly1305_Encrypt(encKey, nonce, NULL, 0, 
                                    ptlv8body, index, objects[5], objects[5]+index);
    //tlv8 encode
    index=0;
    tlv8_add(ptlv8body,&index,6,1,six);
    tlv8_add(ptlv8body,&index,5,objects_len[5],objects[5]);
    tlv8_close(ptlv8body,&index);
    #ifdef DEBUG2
    os_printf("chunked_len: %d\n",index);
    #endif
    //clean up and start json_init before answer
    //wc_SrpTerm(&srp); // also get rid of B and make srp a dynamic memory
    hkc_user_init(myACCname);

    tlv8_send(pcryp, ptlv8body, index);
    //now ptlvbody cleaned in tlv8_send but consider doing that here
}

void crypto_verify1(void *arg)
{
    crypto_parm *pcryp = arg;
    int  *objects_len=pcryp->objects_len;
    char *objects[TLVNUM]= {pcryp->object+0x1c0,//0
                            pcryp->object+0x60, //1
                            NULL,
                            pcryp->object,      //3
                            pcryp->object+0x180,//4
                            pcryp->object+0xb0, //5
                            pcryp->object+0x1c1,//6
                            NULL,
                            NULL,
                            NULL,
                            pcryp->object+0x20, //10
                            pcryp->object+0x1c2 //11
    };
    curve25519_key  mycurvekey;
    curve25519_key  clcurvekey;
    WC_RNG rng;
    byte esalt[] = "Pair-Verify-Encrypt-Salt";
    word32  esaltSz=24;
    byte einfo[] = "Pair-Verify-Encrypt-Info";
    word32  einfoSz=24;
    uint32  oldsystime;

    char *ptlv8body = NULL;
    uint16 index;
    byte nonce[]= "0000PV-Msg02"; //needs to be 12 bytes, will prepad with 0000s
    
    nonce[0]=0; nonce[1]=0;nonce[2]=0;nonce[3]=0; //padding the first four bytes

    #ifdef DEBUG2
    os_printf("pair verify step 1 at %d\r\n",system_get_time()/1000);
    os_printf("Free heap:%d\n", system_get_free_heap_size());
    #endif
    ptlv8body=(char *)zalloc(162); index=0;  //verify number

    int r;
            r = wc_curve25519_init(&clcurvekey);
    if (!r) r = wc_curve25519_init(&mycurvekey);    
    if (!r) r = wc_curve25519_make_key(&rng, 32, &mycurvekey);
    objects_len[5] = objects_maxlen[5]; 
    if (!r) r = wc_curve25519_export_public_ex(&mycurvekey, objects[5], &objects_len[5], EC25519_LITTLE_ENDIAN);
    #ifdef DEBUG2
    os_printf("mycurvekey: ");
    for (r=0; r<objects_len[5] ; r++) os_printf("%02x",objects[5][r]);
    os_printf("\nclcurvekey: ");
    for (r=0; r<objects_len[3] ; r++) os_printf("%02x",objects[3][r]);
    os_printf("\n");
    #endif
    memcpy(pcryp->readKey, objects[3],32); //transfer clcurvekey to verify3step
    memcpy(pcryp->writeKey,objects[5],32); //transfer mycurvekey to verify3step
            r = wc_curve25519_import_public_ex(objects[3], objects_len[3], &clcurvekey, EC25519_LITTLE_ENDIAN);
    pcryp->sessionkey_len = 32;
    oldsystime=system_get_time()/1000;
    #ifdef DEBUG2
    os_printf("system time: %d\n",oldsystime);
    #endif
    if (!r) r = wc_curve25519_shared_secret_ex(&mycurvekey, &clcurvekey, pcryp->sessionkey, &pcryp->sessionkey_len, EC25519_LITTLE_ENDIAN);
    #ifdef DEBUG0
    os_printf("shared secret time: %d\n",(system_get_time()/1000)-oldsystime);
    #endif
    #ifdef DEBUG2
    os_printf("sessionkey: ");
    for (r=0; r<pcryp->sessionkey_len; r++) os_printf("%02x",pcryp->sessionkey[r]);
    os_printf("\n");
    #endif

    // prepare answer5  var material = Buffer.concat([publicKey,usernameData,clientPublicKey]);
    // obj5 = obj5 + myUsername + obj3
    memcpy(objects[5]+objects_len[5],myUsername,myUsername_len); objects_len[5]+=myUsername_len;
    memcpy(objects[5]+objects_len[5],objects[3],objects_len[3]); objects_len[5]+=objects_len[3];
    // transfer my public curve key to objects[3] (client pub curve key not needed anymore)
    objects_len[3] = objects_maxlen[3]; 
            r = wc_curve25519_export_public_ex(&mycurvekey, objects[3], &objects_len[3], EC25519_LITTLE_ENDIAN);
    //sign object5 and use objects[10] for proof storage
    objects_len[10]=objects_maxlen[10];
    oldsystime=system_get_time()/1000;
    #ifdef DEBUG2
    os_printf("system time: %d\n",oldsystime);
    #endif
            r = wc_ed25519_sign_msg(objects[5], objects_len[5], objects[10], &objects_len[10], &myKey);
    #ifdef DEBUG0
    os_printf("sign message time: %d\n",(system_get_time()/1000)-oldsystime);
    #endif
    #ifdef DEBUG2
    os_printf("edsign: %d\n",r);
    os_printf("system time: %d\n",system_get_time()/1000);
    #endif

    if (!r) r = wc_HKDF(SHA512, pcryp->sessionkey, pcryp->sessionkey_len, esalt, esaltSz, einfo, einfoSz, pcryp->verKey, 32);
    
    //fill ptlv8body again with concatenated items 1 and 10 in tlv8 style
    index=0; ptlv8body[index++]=1;   ptlv8body[index++]=myUsername_len;
    for (r=0; r<myUsername_len;r++)  ptlv8body[index++]=myUsername[r];
    ptlv8body[index++]=10;           ptlv8body[index++]=objects_len[10];
    for (r=0; r<objects_len[10];r++) ptlv8body[index++]=objects[10][r];
    // encrypt this and (ab)use objects[5] for storage
    objects_len[5]=index+16;
    r = wc_ChaCha20Poly1305_Encrypt(pcryp->verKey, nonce, NULL, 0, 
                                    ptlv8body, index, objects[5], objects[5]+index);
    // tlv8 encode
    index=0;
    tlv8_add(ptlv8body,&index,6,1,two);
    tlv8_add(ptlv8body,&index,5,objects_len[5],objects[5]);
    tlv8_add(ptlv8body,&index,3,objects_len[3],objects[3]);
    tlv8_close(ptlv8body,&index);
    #ifdef DEBUG2
    os_printf("chunked_len: %d\n",index);
    #endif
    tlv8_send(pcryp, ptlv8body, index);
    //now ptlvbody cleaned in tlv8_send but consider doing that here
}

void crypto_verify3(void *arg)
{
    crypto_parm *pcryp = arg;
    int  *objects_len=pcryp->objects_len;
    char *objects[TLVNUM]= {pcryp->object+0x1c0,//0
                            pcryp->object+0x60, //1
                            NULL,
                            pcryp->object,      //3
                            pcryp->object+0x180,//4
                            pcryp->object+0xb0, //5
                            pcryp->object+0x1c1,//6
                            NULL,
                            NULL,
                            NULL,
                            pcryp->object+0x20, //10
                            pcryp->object+0x1c2 //11
    };
    ed25519_key     clKey;

    char *ptlv8body = NULL;
    uint16 index;
    int verified;
    int shallencrypt=0;
    int found=0;
    int part,k;
    char    flash[80];

    byte rwsalt[]= "Control-Salt";
    word32  rwsaltSz=12;
    byte rinfo[] = "Control-Read-Encryption-Key";
    word32  rinfoSz=27;
    byte winfo[] = "Control-Write-Encryption-Key";
    word32  winfoSz=28;
    uint32  oldsystime;

    byte nonce[]= "0000PV-Msg03"; //needs to be 12 bytes, will prepad with 0000s
    
    nonce[0]=0; nonce[1]=0;nonce[2]=0;nonce[3]=0; //padding the first four bytes
    
    #ifdef DEBUG2
    os_printf("pair verify step 3 at %d\r\n",system_get_time()/1000);
    os_printf("Free heap:%d\n", system_get_free_heap_size());
    #endif
    ptlv8body=(char *)zalloc(160); index=0;  //verify number 110?
    
    int r=0;
    
    if (!r) r = wc_ChaCha20Poly1305_Decrypt(pcryp->verKey, nonce, NULL, 0, 
                    objects[5], objects_len[5]-16, objects[5]+objects_len[5]-16, ptlv8body);
    if (!r)     tlv8_parse(ptlv8body,objects_len[5]-16,objects,objects_len);
    
    //collect clientLTPK from flash and import it in clKey (overwrite previous sessions key)
    for (k=0;k<50;k++) {  //maximum 50 slots
        spi_flash_read(START+k*80,(uint32 *)flash,80);
        #ifdef DEBUG2
        for (r=12;r<48;r++) os_printf("%c",flash[r]);os_printf(" -- ");
        for (r=0;r<80;r++) os_printf("%02x",flash[r]);os_printf("\n");
        #endif
        if (flash[0]==0xff) break; //never used slot
        //if flag is active key then use, else continue
        part=0; while (!flash[part+1] && part<12) part+=2;
        if (flash[part]==flash[part+1]) continue; //inactive slot
        //compare to objects[1] = client user name else continue
        if (memcmp(flash+12,objects[1],36)) continue;
                r = wc_ed25519_init(&clKey);
                r = wc_ed25519_import_public(flash+12+36,ED25519_PUB_KEY_SIZE,&clKey);
        #ifdef DEBUG0
        os_printf("key %d loaded - result: %d\n",k,r);
        #endif
        found=1;
        break;
    }
    if (found) {
        memcpy(objects[5]               ,pcryp->readKey   ,32            ); objects_len[5]=32;  //clcurvekey
        memcpy(objects[5]+objects_len[5],objects[1],objects_len[1]); objects_len[5]+=objects_len[1];
        memcpy(objects[5]+objects_len[5],pcryp->writeKey  ,32            ); objects_len[5]+=32; //mycurvekey
        #ifdef DEBUG2
        os_printf("system time: %d\n",system_get_time()/1000);
        #endif
    
        //ed25519.Verify(concat, clientProof[10], clKey[3])
        oldsystime=system_get_time()/1000;
        #ifdef DEBUG2
        os_printf("system time: %d\n",oldsystime);
        #endif
        r = wc_ed25519_verify_msg(objects[10], objects_len[10], objects[5],objects_len[5], &verified, &clKey);
        #ifdef DEBUG0
        os_printf("verify message time: %d, ",(system_get_time()/1000)-oldsystime);
        os_printf("verified=%d r=%d\n",verified,r);
        #endif
        // else send 7/1/2

        if ( verified==1 ) {
            tlv8_add(ptlv8body,&index,6,1,four);
            shallencrypt=1;
            //prepare keys
//          #ifdef DEBUG2
//          os_printf("sessionkey: ");
//          for (r=0; r<pcryp->sessionkey_len; r++) os_printf("%02x",pcryp->sessionkey[r]);
//          os_printf("\n");
//          #endif
                    r = wc_HKDF(SHA512, pcryp->sessionkey, pcryp->sessionkey_len, rwsalt, rwsaltSz, rinfo, rinfoSz, pcryp->readKey,  32);
            if (!r) r = wc_HKDF(SHA512, pcryp->sessionkey, pcryp->sessionkey_len, rwsalt, rwsaltSz, winfo, winfoSz, pcryp->writeKey, 32);
        } else tlv8_add(ptlv8body,&index,7,1, four); //verification failed
    } else tlv8_add(ptlv8body,&index,7,1, two); //clientLTPK not found

    tlv8_close(ptlv8body,&index);
    #ifdef DEBUG2
    os_printf("chunked_len: %d\n",index);
    #endif
    tlv8_send(pcryp, ptlv8body, index);
    if (shallencrypt)   pcryp->encrypted=1; //else too early because this answer also gets encrypted
    //now ptlvbody cleaned in tlv8_send but consider doing that here
}

void pairadd(void *arg)
{
    crypto_parm *pcryp = arg;
    int  *objects_len=pcryp->objects_len;
    char *objects[TLVNUM]= {pcryp->object+0x1c0,//0
                            pcryp->object+0x60, //1
                            NULL,
                            pcryp->object,      //3
                            pcryp->object+0x180,//4
                            pcryp->object+0xb0, //5
                            pcryp->object+0x1c1,//6
                            NULL,
                            NULL,
                            NULL,
                            pcryp->object+0x20, //10
                            pcryp->object+0x1c2 //11
    };
    char *ptlv8body = NULL;
    uint16 index;
    int part,k,found=0;
    char    flash[80];
    int r;
    
    ptlv8body=(char *)zalloc(16); index=0;
    #ifdef DEBUG2
    os_printf("pair add \r\n");
    os_printf("Free heap:%d\n", system_get_free_heap_size());
    #endif

    for (k=1;k<50;k++) {  //maximum 50 slots first one reserved for paired device, rest for guests
        spi_flash_read(START+k*80,(uint32 *)flash,80); //find if it exists or where list ends
        if (flash[0]==0xff) break; //never used slot
        #ifdef DEBUG2
        for (r=12;r<48;r++) os_printf("%c",flash[r]);os_printf(" -- ");
        for (r=0;r<80;r++) os_printf("%02x",flash[r]);os_printf("\n");
        #endif
        //compare to objects[1] else continue
        if (memcmp(flash+12,objects[1],36)) continue;
        found=1; //maybe compare key to make sure it is the same??
        //if flag is active key then nothing, else activate it
        part=0; while (!flash[part+1] && part<12) part+=2;
        if (flash[part]==flash[part+1]) { //inactive slot
            if (!flash[part+1]) { //right part is zero
                if (part==10) {
                    found=0; continue; //no more space, look for new slot
                } else part+=2;
            } //need to move to next bytes
            flash[part]/=2; //sets left bit to zero?
            #ifdef DEBUG0
            os_printf("key %d: writing flag to flash\n",k);
            #endif
            spi_flash_write(START+k*80,(uint32 *)flash,12);
        } //else nothing because flag already active
    }
    
    if (!found) {
        if (k==50) {
            #ifdef DEBUG0
            os_printf("no more space! reflash?\n");
            #endif
        } else {
            flash[0]=0x7f;
            memset(flash+1,0xff,11); //flag first 12 bytes to 01111111111...1111
            memcpy(flash+12,               objects[1],objects_len[1]);
            memcpy(flash+12+objects_len[1],objects[3],objects_len[3]);
            #ifdef DEBUG0
            os_printf("writing client to flash\n");
            for (r=0;r<80;r++) os_printf("%02x",flash[r]);os_printf("\n");
            #endif
            spi_flash_write(START+k*80,(uint32 *)flash,80);
        }
    }
    tlv8_add(ptlv8body,&index,6,1,two);
    tlv8_close(ptlv8body,&index);
    #ifdef DEBUG2
    os_printf("chunked_len: %d\n",index);
    #endif
    tlv8_send(pcryp, ptlv8body, index);  //we need to encrypt this!
    //now ptlvbody cleaned in tlv8_send but consider doing that here
}

void pairdel(void *arg)
{
    crypto_parm *pcryp = arg;
    int  *objects_len=pcryp->objects_len;
    char *objects[TLVNUM]= {pcryp->object+0x1c0,//0
                            pcryp->object+0x60, //1
                            NULL,
                            pcryp->object,      //3
                            pcryp->object+0x180,//4
                            pcryp->object+0xb0, //5
                            pcryp->object+0x1c1,//6
                            NULL,
                            NULL,
                            NULL,
                            pcryp->object+0x20, //10
                            pcryp->object+0x1c2 //11
    };
    char *ptlv8body = NULL;
    uint16 index;
    int part,k,found=0;
    char    flash[80];
    int r;
    
    ptlv8body=(char *)zalloc(16); index=0;
    #ifdef DEBUG2
    os_printf("pair del!\r\n");
    os_printf("Free heap:%d\n", system_get_free_heap_size());
    #endif
    //if this refers to position 0 then unpair and reset
    pairing=0;  //verify if this is correct!!
    //kill signature in flash and reset device

    for (k=0;k<50;k++) {  //maximum 50 slots first one reserved for paired device, rest for guests
        spi_flash_read(START+k*80,(uint32 *)flash,80); //find if it exists or where list ends
        if (flash[0]==0xff) break; //never used slot
        #ifdef DEBUG2
        for (r=12;r<48;r++) os_printf("%c",flash[r]);os_printf(" -- ");
        for (r=0;r<80;r++) os_printf("%02x",flash[r]);os_printf("\n");
        #endif
        //compare to objects[1] else continue
        if (memcmp(flash+12,objects[1],36)) continue;
        found=1;
        if (k==0) { //this is an unpair activity
            #ifdef DEBUG0
            os_printf("unpair mutilate signature and reset\n");
            #endif
            spi_flash_write(START+4080,(uint32 *)flash+12,16); //mutilate the signature
            #ifdef DEBUG2
            spi_flash_read(START+4080,(uint32 *)flash,16); //did it work?
            for (r=0;r<16;r++) os_printf("%02x",flash[r]);os_printf("\n");
            #endif
            pairing = 1; //this will trigger the reset
            break;
        }
        //if flag is inactive key then nothing, else deactivate it
        part=0; while (!flash[part+1] && part<12) part+=2;
        if (flash[part+1]!=flash[part]) { //active slot
            flash[part+1] =flash[part];  //sets left bit to zero?
            #ifdef DEBUG2
            os_printf("key %d, writing flag to flash\n",k);
            #endif
            spi_flash_write(START+k*80,(uint32 *)flash,12);
        } //else nothing because flag already inactive
    }
    
    tlv8_add(ptlv8body,&index,6,1,two);
    tlv8_close(ptlv8body,&index);
    #ifdef DEBUG2
    os_printf("chunked_len: %d\n",index);
    #endif
    tlv8_send(pcryp, ptlv8body, index);
    //now ptlvbody cleaned in tlv8_send but consider doing that here
    if (pairing) {
        os_delay_us(0xffff); //allow some time to send confirmation to client?
        system_restart();
        #ifdef DEBUG0   
        os_printf("this should not be seen after an unpair reset\n");
        #endif
    }
}

void decrypt(void *arg, char *data, unsigned short *length)  // length will change!
{
    crypto_parm *pcryp = arg;
    int r,total,offset,len;
    byte *buffer = NULL;

    byte nonce[12]={0,0,0,0,0,0,0,0,0,0,0,0};
    #ifdef DEBUG2
    os_printf("raw: ");
    for (r=0;r<*length;r++) os_printf("%02x",data[r]);
    os_printf("\n");/**/
    #endif
    //do decryption things and result is in data again

    buffer = (byte *)zalloc(*length);
    total=*length; *length=0;
    for (offset=0;offset<total;){
        len = 256*data[1]+data[0]; //Little Endian
        nonce[4]=pcryp->countwr%256;nonce[5]=pcryp->countwr++/256; //should fix to grow beyond 64k but not urgent
        #ifdef DEBUG2
        os_printf("nonce %02x %02x\n",nonce[4],nonce[5]);
        #endif
        r = wc_ChaCha20Poly1305_Decrypt(pcryp->writeKey, nonce, data+offset, 2, 
                        data+offset+2, len, data+offset+2+len, buffer);
        for (r=0;r<len;r++) data[r+*length]=buffer[r];
        *length+=len; offset+=len+0x12;
    }
    #ifdef DEBUG0
    //os_printf("txt:\n");
    for (r=0;r<*length;r++) os_printf("%c",data[r]);
    os_printf("\n");
    #endif
    #ifdef DEBUG2
/*  os_printf("dec: ");
    for (r=0;r<*length;r++) os_printf("%02x",data[r]);
    os_printf("\n");/**/
    os_printf("Free heap:%d\n", system_get_free_heap_size());/**/
    #endif

    free(buffer);
}

void encrypt(void *arg, char *data, unsigned short *length)
{
    crypto_parm *pcryp = arg;
    int r,total,offset,len;
    byte *in = NULL;
    byte nonce[12]={0,0,0,0,0,0,0,0,0,0,0,0};
    char    lelen[2];
    
    in = (byte *)zalloc(*length);
    memcpy(in, data, *length);
    //os_printf("system time: %d\n",system_get_time()/1000);
    #ifdef DEBUG0
    //os_printf("txt: ");
    for (r=0;r<*length;r++) os_printf("%c",in[r]);
    os_printf("\n"); /**/
    #endif
    //os_printf("system time: %d\n",system_get_time()/1000);
    #ifdef DEBUG2
    os_printf("length: 0x%04x\n",*length);
    #endif

    total=*length; *length=0;
    for (offset=0;offset<total;){
        len=total-offset; len = (len<0x400)?len:0x400; lelen[0]=len%256; lelen[1]=len/256;
        nonce[4]=pcryp->countrd%256;nonce[5]=pcryp->countrd++/256; //should fix to grow beyond 64k but not urgent
        #ifdef DEBUG2
        os_printf("nonce %02x %02x\n",nonce[4],nonce[5]);
        #endif
        memcpy(data+*length,lelen,2);
        r = wc_ChaCha20Poly1305_Encrypt(pcryp->readKey, nonce, lelen, 2, 
                    in+offset, len, data+*length+2, data+*length+2+len);
        *length+=len+0x12; offset+=len;
    }

    free(in);
}

