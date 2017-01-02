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

#ifndef __HKC_H__
#define __HKC_H__

#include "cJSON.h"

/******************************************************************************
 * FunctionName : hkc_init
 * Description  : start using hkc. call in user_init
 *                postpone non-essential init to hkc_user_init
 * Parameters   : the accessory name
 * Returns      : nothing
*******************************************************************************/
void    hkc_init(char *accname);

/******************************************************************************
 * FunctionName : hkc_user_init
 * Description  : this is the callback after hkc_init()
 * Parameters   : the accessory name
 * Returns      : nothing
*******************************************************************************/
void    hkc_user_init(char *accname);

/******************************************************************************
 * FunctionName : change_value
 * Description  : push to the hkc server that the value has changed
 * Parameters   : aid   -- accessory id
 *                iid   -- item id
 *                value -- cJSON object with the value
 * Returns      : nothing
*******************************************************************************/
void    change_value(int aid, int iid, cJSON *value);

/******************************************************************************
 * FunctionName : send_events
 * Description  : tell the hkc server to send events for the characteristic
 * Parameters   : arg -- NULL
 *                aid -- accessory id
 *                iid -- item id
 * Returns      : nothing
*******************************************************************************/
void    send_events(void *arg, int aid, int iid);

/******************************************************************************
 * FunctionName : initAccessories
 * Description  : mandatory first step
 * Parameters   : none
 * Returns      : cJSON accessories container
*******************************************************************************/
cJSON   *initAccessories();

/******************************************************************************
 * FunctionName : addAccessory
 * Description  : add an accessory to the accessories container
 * Parameters   : accs  -- cJSON accessories container
 *                ++aid -- accessory id
 * Returns      : cJSON services container
*******************************************************************************/
cJSON   *addAccessory(cJSON *accs, int aid);

/******************************************************************************
 * FunctionName : addService
 * Description  : add a service to the services container
 * Parameters   : sers  -- cJSON services container
 *                ++iid -- item id
 *                brand   -- sprintf format string, takes sType - see below 
 *                sType   -- service Type - see below
 * Returns      : cJSON characteristics container
*******************************************************************************/
cJSON   *addService(cJSON *sers, int iid, char *brand, int sType);

/******************************************************************************
 * Typedef      : acc_cb
 * Description  : prototype of the callback used to communicate with hkc
 * Parameters   : aid   -- accessory id
 *                iid   -- item id
 *                value -- cJSON object with the value
 *                mode  -- 0=init, 1=change, 2=refresh
 * Returns      : nothing
*******************************************************************************/
typedef void (* acc_cb)(int aid, int iid, cJSON *value, int mode);

/******************************************************************************
 * FunctionName : addCharacteristic
 * Description  : add a characteristic to the characteristics container
 * Parameters   : chas  -- cJSON characteristics container
 *                aid   -- accessory id
 *                ++iid -- item id
 *                brand   -- sprintf format string, takes cType - see below 
 *                cType   -- characteristic Type - see below
 *                valuestring   -- initial value represented as a string
 *                change_cb   -- callback function (see above for prototype)
 * Returns      : nothing
*******************************************************************************/
void    addCharacteristic(cJSON *chas, int aid, int iid, char *brand, int cType, char *valuestring, acc_cb change_cb);

/******************************************************************************/
//brand name
#define APPLE   "000000%02X-0000-1000-8000-0026BB765291"

//sType name
#define LIGHTBULB_S                             0x43
#define SWITCH_S                                0x49
#define THERMOSTAT_S                            0x4A
#define GARAGE_DOOR_OPENER_S                    0x41
#define ACCESSORY_INFORMATION_S                 0x3E
#define FAN_S                                   0x40
#define OUTLET_S                                0x47
#define LOCK_MECHANISM_S                        0x45
#define LOCK_MANAGEMENT_S                       0x44

//cType name                                    Type    //mxlen format  read/write/event
#define ADMIN_ONLY_ACCESS_C                     0x01
#define AUDIO_FEEDBACK_C                        0x05
#define BRIGHTNESS_C                            0x08
#define COOLING_THRESHOLD_C                     0x0D
#define CURRENT_DOOR_STATE_C                    0x0E
#define CURRENT_LOCK_MECHANISM_STATE_C          0x1D
#define CURRENT_RELATIVE_HUMIDITY_C             0x10
#define CURRENT_TEMPERATURE_C                   0x11
#define HEATING_THRESHOLD_C                     0x12
#define HUE_C                                   0x13
#define IDENTIFY_C                              0x14    //  1   boolean w
#define LOCK_MANAGEMENT_AUTO_SECURE_TIMEOUT_C   0x1A
#define LOCK_MANAGEMENT_CONTROL_POINT_C         0x19
#define LOCK_MECHANISM_LAST_KNOWN_ACTION_C      0x1C
#define LOGS_C                                  0x1F
#define MANUFACTURER_C                          0x20    //255   string  r
#define MODEL_C                                 0x21    //255   string  r
#define MOTION_DETECTED_C                       0x22
#define NAME_C                                  0x23    //255   string  r
#define OBSTRUCTION_DETECTED_C                  0x24
#define OUTLET_IN_USE_C                         0x26
#define POWER_STATE_C                           0x25    //  1   boolean rwe
#define ROTATION_DIRECTION_C                    0x28
#define ROTATION_SPEED_C                        0x29
#define SATURATION_C                            0x2F
#define SERIAL_NUMBER_C                         0x30    //255   string  r
#define TARGET_DOORSTATE_C                      0x32
#define TARGET_LOCK_MECHANISM_STATE_C           0x1E
#define TARGET_RELATIVE_HUMIDITY_C              0x34
#define TARGET_TEMPERATURE_C                    0x35
#define TEMPERATURE_UNITS_C                     0x36
#define VERSION_C                               0x37
#define CURRENTHEATINGCOOLING_C                 0x0F
#define TARGETHEATINGCOOLING_C                  0x33

#endif
