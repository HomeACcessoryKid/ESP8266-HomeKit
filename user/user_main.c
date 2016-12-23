/*
Copyright 2016 HomeACcessoryKid - HacK - homeaccessorykid@gmail.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

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

/*****************************************************************************************
 * Welcome to the HomeACcessoryKid hkc demo
 * With a few lines of code we demonstrate the easy setup of your ESP8266 as an accessory.
 * Start defining your accessory in hkc_user_init and execute other pending init tasks.
 * For each Service characteristic a callback function is defined.
 * An ACC_callback will be called in different modes.
 * - mode=0: initialize your service (init)
 * - mode=1: a request for a change  is received on which you could act (write)
 * - mode=2: a request for a refresh is received where you might update  (read)
 * A callback should return QUICKLY, else use a Task as demonstrated below.
 *
 * If something changes from inside, you can use change_value and send_events in return.
 * You use aid and iid to know which characteristic to handle and cJSON for the value.
 *
 * Use iOS10 Home app or Eve or other app to test all the features and enjoy
*****************************************************************************************/
 
#include "esp_common.h"
#include "hkc.h"
#include "gpio.h"
#include "queue.h"

xQueueHandle identifyQueue;

struct gpio {
	int	aid;
	int iid;
} gpio2;

void led_task(void *arg) //make transfer of gpio via arg, starting as a static variable in led routine
{
	int	i,original;
	cJSON	*value;

	os_printf("led_task started\n");
	value=cJSON_CreateBool(0); //value doesn't matter
	while(1) {
		vTaskDelay(1500); //15 sec
		original=GPIO_INPUT_GET(GPIO_ID_PIN(2)); //get original state
//		os_printf("original:%d\n",original);
		value->type=original^1;
		GPIO_OUTPUT_SET(GPIO_ID_PIN(2),original^1); // and toggle
		change_value(    gpio2.aid,gpio2.iid,value);
		send_events(NULL,gpio2.aid,gpio2.iid);
	}
}

void led(int aid, int iid, cJSON *value, int mode)
{
 	switch (mode) {
 		case 1: { //changed by gui
			char *out; out=cJSON_Print(value);	os_printf("led %s\n",out);	free(out);	// Print to text, print it, release the string.
			if (value) GPIO_OUTPUT_SET(GPIO_ID_PIN(2), value->type);
		}break;
 		case 0: { //init
			PIN_FUNC_SELECT(GPIO_PIN_REG_2,FUNC_GPIO2);
			PIN_PULLUP_EN(GPIO_PIN_REG_2);
			led(aid,iid,value,1);
			gpio2.aid=aid; gpio2.iid=iid;
			xTaskCreate(led_task,"led",512,NULL,2,NULL);
		}break;
		case 2: { //update
			//do nothing
		}break;
		default: {
			//print an error?
		}break;
	}
}

void identify_task(void *arg)
{
	int	i,original;

	os_printf("identify_task started\n");
	while(1) {
		while(!xQueueReceive(identifyQueue,NULL,10));//wait for a queue item
		original=GPIO_INPUT_GET(GPIO_ID_PIN(2)); //get original state
		for (i=0;i<2;i++) {
			GPIO_OUTPUT_SET(GPIO_ID_PIN(2),original^1); // and toggle
			vTaskDelay(30); //0.3 sec
			GPIO_OUTPUT_SET(GPIO_ID_PIN(2),original^0);
			vTaskDelay(30); //0.3 sec
		}
	}
}

void identify(int aid, int iid, cJSON *value, int mode)
{
 	switch (mode) {
 		case 1: { //changed by gui
			xQueueSend(identifyQueue,NULL,0);
		}break;
 		case 0: { //init
		identifyQueue = xQueueCreate( 1, 0 );
		PIN_FUNC_SELECT(GPIO_PIN_REG_2,FUNC_GPIO2);
		PIN_PULLUP_EN(GPIO_PIN_REG_2);
		xTaskCreate(identify_task,"identify",256,NULL,2,NULL);
		}break;
		case 2: { //update
			//do nothing
		}break;
		default: {
			//print an error?
		}break;
	}
}

extern	cJSON		*root;
void	hkc_user_init(char *accname)
{
	//do your init thing beyond the bear minimum
	//avoid doing it in user_init else no heap left for pairing
	cJSON *accs,*sers,*chas,*value;
	int aid=0,iid=0;

	accs=initAccessories();
	
	sers=addAccessory(accs,++aid);
	//service 0 describes the accessory
	chas=addService(      sers,++iid,APPLE,ACCESSORY_INFORMATION_S);
	addCharacteristic(chas,aid,++iid,APPLE,NAME_C,accname,NULL);
	addCharacteristic(chas,aid,++iid,APPLE,MANUFACTURER_C,"HacK",NULL);
	addCharacteristic(chas,aid,++iid,APPLE,MODEL_C,"Rev-1",NULL);
	addCharacteristic(chas,aid,++iid,APPLE,SERIAL_NUMBER_C,"1",NULL);
	addCharacteristic(chas,aid,++iid,APPLE,IDENTIFY_C,NULL,identify);
	//service 1
	chas=addService(      sers,++iid,APPLE,SWITCH_S);
	addCharacteristic(chas,aid,++iid,APPLE,NAME_C,"led",NULL);
	addCharacteristic(chas,aid,++iid,APPLE,POWER_STATE_C,"1",led);
	//service 2
	chas=addService(      sers,++iid,APPLE,LIGHTBULB_S);
	addCharacteristic(chas,aid,++iid,APPLE,NAME_C,"light",NULL);
	addCharacteristic(chas,aid,++iid,APPLE,POWER_STATE_C,"0",NULL);
	addCharacteristic(chas,aid,++iid,APPLE, BRIGHTNESS_C,"0",NULL);

	char *out;
	out=cJSON_Print(root);	os_printf("%s\n",out);	free(out);	// Print to text, print it, release the string.

// 	for (iid=1;iid<MAXITM+1;iid++) {
// 		out=cJSON_Print(acc_items[iid].json);
// 		os_printf("1.%d=%s\n",iid,out); free(out);
// 	}
}

/******************************************************************************
 * FunctionName : user_init
 * Description  : entry of user application, init user function here
 * Parameters   : none
 * Returns      : none
*******************************************************************************/
void user_init(void)
{	
    os_printf("start of user_init @ %d\n",system_get_time()/1000);
    
//use this block only once to set your favorite access point or put your own selection routine
/*    wifi_set_opmode(STATION_MODE); 
    struct station_config *sconfig = (struct station_config *)zalloc(sizeof(struct station_config));
    sprintf(sconfig->ssid, ""); //don't forget to set this if you use it
    sprintf(sconfig->password, ""); //don't forget to set this if you use it
    wifi_station_set_config(sconfig);
    free(sconfig);
    wifi_station_connect(); /**/
    
	//try to only do the bare minimum here and do the rest in hkc_user_init
	// if not you could easily run out of stack space during pairing-setup
    hkc_init("HomeACcessory");
    
    os_printf("end of user_init @ %d\n",system_get_time()/1000);
}

/***********************************************************************************
 * FunctionName : user_rf_cal_sector_set forced upon us by espressif since RTOS1.4.2
 * Description  : SDK just reversed 4 sectors, used for rf init data and paramters.
 *                We add this function to force users to set rf cal sector, since
 *                we don't know which sector is free in user's application.
 *                sector map for last several sectors : ABCCC
 *                A : rf cal	B : rf init data	C : sdk parameters
 * Parameters   : none
 * Returns      : rf cal sector
***********************************************************************************/
uint32 user_rf_cal_sector_set(void) {
    extern char flashchip;
    SpiFlashChip *flash = (SpiFlashChip*)(&flashchip + 4);
    // We know that sector size is 4096
    //uint32_t sec_num = flash->chip_size / flash->sector_size;
    uint32_t sec_num = flash->chip_size >> 12;
    return sec_num - 5;
}
