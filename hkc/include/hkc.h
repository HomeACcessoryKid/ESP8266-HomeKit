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
 *              : optional int<10, the 'Accessory Category' see below 
 * Returns      : nothing
*******************************************************************************/
void    hkc_init(char *accname, ...);

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
 * Typedef      : acc_item
 * Description  : struct to refer to char items based on iid
 * Parameters   : json      -- pointer to the jSON of this char
 *                events    -- which CIDs are subscribed to an event
 *                change_cb -- the callback function of this char
 * Returns      : nothing
*******************************************************************************/
typedef struct _acc_item {
    cJSON   *json;
    uint32  events;
    acc_cb  change_cb;
} acc_item;

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

//accessory category
#define OTHER_CAT                                     1
#define BRIDGE_CAT                                    2
#define FAN_CAT                                       3
#define GARAGE_CAT                                    4
#define LIGHTBULB_CAT                                 5
#define DOOR_LOCK_CAT                                 6
#define OUTLET_CAT                                    7
#define SWITCH_CAT                                    8
#define THERMOSTAT_CAT                                9

//brand name
#define APPLE   "%08X-0000-1000-8000-0026BB765291"

//sType name
#define ACCESSORY_INFORMATION_S                     0x3E
#define FAN_S                                       0x40
#define GARAGE_DOOR_OPENER_S                        0x41
#define LIGHTBULB_S                                 0x43
#define LOCK_MANAGEMENT_S                           0x44
#define LOCK_MECHANISM_S                            0x45
#define OUTLET_S                                    0x47
#define SWITCH_S                                    0x49
#define THERMOSTAT_S                                0x4A
#define AIR_QUALITY_SENSOR_S                        0x8D
#define SECURITY_SYSTEM_S                           0x7E
#define CARBON_MONOXIDE_SENSOR_S                    0x7F
#define CONTACT_SENSOR_S                            0x80
#define DOOR_S                                      0x81
#define HUMIDITY_SENSOR_S                           0x82
#define LEAK_SENSOR_S                               0x83
#define LIGHT_SENSOR_S                              0x84
#define MOTION_SENSOR_S                             0x85
#define OCCUPANCY_SENSOR_S                          0x86
#define SMOKE_SENSOR_S                              0x87
#define STATELESS_PROGRAMMABLE_SWITCH_S             0x89
#define TEMPERATURE_SENSOR_S                        0x8A
#define WINDOW_S                                    0x8B
#define WINDOW_COVERING_S                           0x8C
#define BATTERY_SERVICE_S                           0x96
#define CARBON_DIOXIDE_SENSOR_S                     0x97
#define CAMERA_RTP_STREAM_MANAGEMENT_S              0x110
#define MICROPHONE_S                                0x112
#define SPEAKER_S                                   0x113
#define DOORBELL_S                                  0x121
#define FAN_V2_S                                    0xB7
#define SLAT_S                                      0xB9
#define FILTER_MAINTENANCE_S                        0xBA
#define AIR_PURIFIER_S                              0xBB
#define SERVICE_LABEL_S                             0xCC

//cType name                                        Type    //mxlen format  read/write/event
#define ADMINISTRATOR_ONLY_ACCESS_C                 0x01
#define AUDIO_FEEDBACK_C                            0x05
#define BRIGHTNESS_C                                0x08    //n/a   int     rwe
#define COOLING_THRESHOLD_TEMPERATURE_C             0x0D
#define CURRENT_DOOR_STATE_C                        0x0E
#define CURRENT_HEATING_COOLING_STATE_C             0x0F    //n/a   uint8   re
#define CURRENT_RELATIVE_HUMIDITY_C                 0x10
#define CURRENT_TEMPERATURE_C                       0x11    //n/a   float   re
#define FIRMWARE_REVISION_C                         0x52
#define HARDWARE_REVISION_C                         0x53
#define HEATING_THRESHOLD_TEMPERATURE_C             0x12
#define HUE_C                                       0x13    //n/a   float   rwe
#define IDENTIFY_C                                  0x14    //n/a   boolean w
#define LOCK_CONTROL_POINT_C                        0x19
#define LOCK_CURRENT_STATE_C                        0x1D
#define LOCK_LAST_KNOWN_ACTION_C                    0x1C
#define LOCK_MANAGEMENT_AUTO_SECURITY_TIMEOUT_C     0x1A
#define LOCK_TARGET_STATE                           0x1E
#define LOGS_C                                      0x1F
#define MANUFACTURER_C                              0x20    //64    string  r
#define MODEL_C                                     0x21    //64    string  r
#define MOTION_DETECTED_C                           0x22    //n/a   boolean re
#define NAME_C                                      0x23    //64    string  r
#define OBSTRUCTION_DETECTED_C                      0x24
#define ON_C                                        0x25    //n/a   boolean rwe
#define POWER_STATE_C                               0x25    //deprecated for ON_C
#define OUTLET_IN_USE_C                             0x26
#define ROTATION_DIRECTION_C                        0x28    //n/a   int     rwe
#define ROTATION_SPEED_C                            0x29    //n/a   float   rwe
#define SATURATION_C                                0x2F    //n/a   float   rwe
#define SERIAL_NUMBER_C                             0x30    //64    string  r
#define TARGET_DOORSTATE_C                          0x32
#define TARGET_HEATING_COOLING_STATE_C              0x33    //n/a   uint8   rwe
#define TARGET_RELATIVE_HUMIDITY_C                  0x34
#define TARGET_TEMPERATURE_C                        0x35    //n/a   float   rwe
#define TEMPERATURE_DISPLAY_UNITS_C                 0x36    //n/a   uint8   rwe
#define VERSION_C                                   0x37
#define AIR_PARTICULATE_DENSITY_C                   0x64
#define AIR_PARTICULATE_SIZE_C                      0x65
#define SECURITY_SYSTEM_CURRENT_STATE_C             0x66
#define SECURITY_SYSTEM_TARGET_STATE_C              0x67
#define BATTERY_LEVER_C                             0x68
#define CARBON_MONOXIDE_DETECTED_C                  0x69    //n/a   uint8   re
#define CONTACT_SENSOR_STATE_C                      0x6A
#define CURRENT_AMBIENT_LIGHT_LEVEL_C               0x6B    //n/a   float   re
#define CURRENT_HORIZONTAL_TILT_ANGLE_C             0x6C
#define CURRENT_POSITION_C                          0x6D
#define CURRENT_VERTICAL_TILT_ANGLE_C               0x6E
#define HOLD_POSITION_C                             0x6F
#define LEAK_DETECTED_C                             0x70
#define OCCUPANCY_DETECTED_C                        0x71
#define POSITION_STATE_C                            0x72
#define PROGRAMMABLE_SWITCH_EVENT_C                 0x73
#define STATUS_ACTIVE_C                             0x75    //n/a   boolean re
#define SMOKE_DETECTED_C                            0x76
#define STATUS_FAULT_C                              0x77
#define STATUS_JAMMED_C                             0x78
#define STATUS_LOW_BATTERY_C                        0x79
#define STATUS_TAMPERED_C                           0x7A    //n/a   uint8   re
#define TARGET_HORIZONTAL_TILT_ANGLE_C              0x7B
#define TARGET_POSITION_C                           0x7C
#define TARGET_VERTICAL_TILT_ANGLE_C                0x7D
#define SECURITY_SYSTEM_ALARM_TYPE_C                0x8E
#define CHARGING_STATE_C                            0x8F
#define CARBON_MONOXIDE_LEVEL_C                     0x90
#define CARBON_MONOXIDE_PEAK_LEVEL_C                0x91
#define CARBON_DIOXIDE_DETECTED_C                   0x92
#define CARBON_DIOXIDE_LEVEL_C                      0x93
#define CARBON_DIOXIDE_PEAK_LEVEL_C                 0x94
#define AIR_QUALITY_C                               0x95
#define STREAMING_STATUS_C                          0x120
#define SUPPORTED_VIDEO_STREAMING_CONFIGURATION_C   0x114
#define SUPPORTED_AUDIO_STREAMING_CONFIGURATION_C   0x115
#define SUPPORTED_RTP_CONFIGURATION_C               0x116
#define SELECTED_RTP_STREAM_CONFIGURATION_C         0x117
#define SETUP_ENDPOINTS_C                           0x118
#define VOLUME_C                                    0x119
#define MUTE_C                                      0x11A
#define NIGHT_VISION_C                              0x11B
#define OPTICAL_ZOOM_C                              0x11C
#define DIGITAL_ZOOM_C                              0x11D
#define IMAGE_ROTATION_C                            0x11E
#define IMAGE_MIRRORING_C                           0x11F
#define ACCESSORY_FLAGS_C                           0xA6
#define LOCK_PHYSICAL_CONTROLS_C                    0xA7
#define CURRENT_AIR_PURIFIER_STATE_C                0xA9
#define CURRENT_SLAT_STATE_C                        0xAA
#define SLAT_TYPE_C                                 0xC0
#define FILTER_LIFE_LEVEL_C                         0xAB
#define FILTER_CHANGE_INDICATION_C                  0xAC
#define RESET_FILTER_INDICATION_C                   0xAD
#define TARGET_AIR_PURIFIER_STATE_C                 0xA8
#define TARGET_FAN_STATE_C                          0xBF
#define CURRENT_FAN_STATE_C                         0xAF
#define ACTIVE_C                                    0xB0
#define SWING_MODE_C                                0xB6
#define CURRENT_TILT_ANGLE_C                        0xC1
#define TARGET_TILT_ANGLE_C                         0xC2
#define OZONE_DENSITY_C                             0xC3
#define NITROGEN_DIOXIDE_DENSITY_C                  0xC4
#define SULPHUR_DIOXIDE_DENSITY_C                   0xC5
#define PM2_5_DENSITY_C                             0xC6
#define PM10_DENSITY_C                              0xC7
#define VOC_DENSITY_C                               0xC8
#define SERVICE_LABEL_INDEX_C                       0xCB
#define SERVICE_LABEL_NAMESPACE_C                   0xCD
#define COLOR_TEMPERATURE_C                         0xCE

#endif
