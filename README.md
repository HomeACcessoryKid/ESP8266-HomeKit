# ESP8266-HomeKit [![Build Status](https://travis-ci.org/HomeACcessoryKid/ESP8266-HomeKit-Demo.svg?branch=master)](https://travis-ci.org/HomeACcessoryKid/ESP8266-HomeKit-Demo)
HomeKit server foundation on ESP8266 with an API approach

## UPDATE 17 Dec 2017

Please read the message in [issue 41](https://github.com/HomeACcessoryKid/ESP8266-HomeKit/issues/41) about the switchover to Maxim Kulkin code base.

-------

Public Apple's HomeKit protocol code has been around for some time for more potent processors (notably [HAP-NodeJS](https://github.com/KhaosT/HAP-NodeJS)). This is a rewrite for the ESP8266 to make the server foundation.
This project uses [ESP8266_RTOS_SDK](https://github.com/espressif/ESP8266_RTOS_SDK) and
[WolfCrypt 3.9.8](https://github.com/wolfSSL/wolfssl/releases/tag/v3.9.8) for the crypto. It will however NOT deliver a certified HomeKit device. 

For build instructions please refer to the [wiki](https://github.com/HomeACcessoryKid/ESP8266-HomeKit/wiki).

# Demo

If you use the Demo Code from [ESP8266-HomeKit-Demo](https://github.com/HomeACcessoryKid/ESP8266-HomeKit-Demo) you get this...
[![HomeKit Demo](https://img.youtube.com/vi/Xnr-utWDIR8/0.jpg)](https://www.youtube.com/watch?v=Xnr-utWDIR8)

# About the code

The code provides all the services required to pair iOS with an IP device and to operate that device once paired with multiple iOS devices. It runs on even the smallest ESP8266 device like the ESP-01. It creates
an API level to create your HomeKit device without descending to the lower levels of the HAP protocol.  
See the [ESP8266-HomeKit-Demo](https://github.com/HomeACcessoryKid/ESP8266-HomeKit-Demo) for the details.

## Timings

Here are some preliminary timings. 

### Pairing

Pairing is dominated by the SRP algorithm which is very slow and expensive. Fortunately this only happens once when the iOS device is being associated with the HomeKit device:

- Time1: 25 seconds from boot till start of server, so that initial interaction is split second.

- Time2: 30 seconds (based on a build with DEBUG logging which is slow).

### Verify

Verify happens every time an iOS device reconnected to the HomeKit device. Ideally this should be as fast as possible.

- Time: 1.2 seconds

## Memory

The HomeKit code is approximately 400K and about 18K of RAM is left for other purposes. During Pairing so much RAM is used that it is required to launch most code after pairing is done.

# Thanks

I want to thank a number of projects which made this possible:

1. [HAP-NodeJS](https://github.com/KhaosT/HAP-NodeJS) - which documents the HomeKit protocols for IP and allowed me to guess how they
were implemented.

2. https://github.com/aanon4/HomeKit - which inspired this README and should inspire us to look into assembly.

3. [ESP8266_RTOS_SDK](https://github.com/espressif/ESP8266_RTOS_SDK) - Espressif for their great product

4. [WolfCrypt](https://www.wolfssl.com/wolfSSL/Products-wolfcrypt.html) - For a great one stop crypto library

# Notes

Please note that this software was produced without any reference to any proprietary documentation or information. I am not a MFi licensee, nor do I have access to any related information.

Espressif uses MIT license. WolfCrypt uses GPLv2 or higher license. For the purpose of this distribution you should use GPLv3.  
This is based on the changes I had to make to Wolfcrypt and to be compatible with Apache-2.0 license.

# License

Copyright 2016-2017 HomeACcessoryKid - HacK - homeaccessorykid@gmail.com

Licensed under the Apache License, Version 2.0 (the "License");  
you may not use this file except in compliance with the License.  
You may obtain a copy of the License at  

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software  
distributed under the License is distributed on an "AS IS" BASIS,  
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  
See the License for the specific language governing permissions and  
limitations under the License.
