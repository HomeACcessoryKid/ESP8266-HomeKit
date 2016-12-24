# How to build and deploy ESP8266-HomeKit

==============================
Copyright 2016 HomeACcessoryKid - HacK - homeaccessorykid@gmail.com

Licensed under the Apache License, Version 2.0 (the "License");  
you may not use this file except in compliance with the License.  
You may obtain a copy of the License at  

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software  
distributed under the License is distributed on an "AS IS" BASIS,  
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  
See the License for the specific language governing permissions and  
limitations under the License.

==============================

## Directory Structure

### ESP8266/RTOS SDK

When applying this software on the [ESP8266/RTOS SDK](https://github.com/espressif/ESP8266_RTOS_SDK) it is assumed that this environment already works as recommended. The directories from `hkc` folder should be duplicated in `include` and `third_party` folders respectively within ESP8266_RTOS_SDK. The content can be hardlinked to serve github.

```
.
├── hkc
│   ├── include
│   │   └── hkc
│   │       ├── hkc.h
│   │       └── user_settings.h
│   └── third_party
│       └── hkc
│           ├── Makefile
│           ├── hk.h
│           ├── hkc.c
│           └── todo.txt
```

ESP8266-HomeKit will need more space than originally foreseen in ESP8266_RTOS_SDK 1.5.0 which was to start irom at 0x20000. To address this it is needed to change the `ld/eagle.app.v6.ld` file:

```bash
diff ld/eagle.app.v6.ld ld/eagle.app.v6.ld.0
29,30c29
< /*irom0_0_seg :                       	org = 0x40220000, len = 0x5C000 */
<   irom0_0_seg :                       	org = 0x40214000, len = 0x67000
---
>   irom0_0_seg :                       	org = 0x40220000, len = 0x5C000
```

for convenience also change the master Makefile:
```bash
diff ESP8266/source/ESP8266_RTOS_SDK-master-v1.5.0/Makefile Makefile 
271c271
< 	@echo "eagle.irom0text.bin---->0x20000"
---
> 	@echo "eagle.irom0text.bin---->0x14000"
```

### wolfSSL

[Included](https://github.com/HomeACcessoryKid/ESP8266-HomeKit/tree/master/wolfcrypt) is a subsection of the [wolfSSL 3.9.8](https://www.wolfssl.com/wolfSSL/Blog/Entries/2016/7/29_wolfSSL_Version_3.9.8_is_Here!.html) distribution for convenience.
Please download your own copy and verify the equality of the files (*.0 is original)
Note that additional src files should be removed to prevent excess irom size.

```
.
└── wolfcrypt
    ├── COPYING
    ├── LICENSING
    ├── Makefile
    ├── include
    │   └── wolfssl
    │       ├── ssl.h
    │       ├── version.h
    │       └── wolfcrypt
    │           ├── arc4.h
    │           ├── asn.h
    │           ├── asn_public.h
    │           ├── chacha.h
    │           ├── chacha20_poly1305.h
    │           ├── curve25519.h
    │           ├── ed25519.h
    │           ├── error-crypt.h
    │           ├── fe_operations.h
    │           ├── ge_operations.h
    │           ├── hash.h
    │           ├── hmac.h
    │           ├── integer.h
    │           ├── logging.h
    │           ├── memory.h
    │           ├── misc.h
    │           ├── mpi_class.h
    │           ├── mpi_superclass.h
    │           ├── poly1305.h
    │           ├── random.h
    │           ├── rsa.h
    │           ├── settings.h
    │           ├── settings.h.0
    │           ├── sha.h
    │           ├── sha256.h
    │           ├── sha512.h
    │           ├── srp.h
    │           ├── types.h
    │           ├── visibility.h
    │           └── wc_port.h
    └── src
        ├── Makefile
        ├── chacha.c
        ├── chacha20_poly1305.c
        ├── curve25519.c
        ├── ed25519.c
        ├── fe_operations.c
        ├── ge_operations.c
        ├── ge_operations.c.0
        ├── hash.c
        ├── hmac.c
        ├── integer.c
        ├── misc.c
        ├── misc.c.0
        ├── poly1305.c
        ├── random.c
        ├── sha256.c
        ├── sha512.c
        └── srp.c
```
```diff

$ diff ESP8266-HomeKit/wolfcrypt/src/ge_operations.c ESP8266-HomeKit/wolfcrypt/src/ge_operations.c.0 
770c770
< static ge_precomp ICACHE_RODATA_ATTR base[32][8] = {
---
> static ge_precomp base[32][8] = {
2225c2225
< static ge_precomp ICACHE_RODATA_ATTR Bi[8] = {
---
> static ge_precomp Bi[8] = {

$ diff ESP8266-HomeKit/wolfcrypt/src/misc.c ESP8266-HomeKit/wolfcrypt/src/misc.c.0 
48,50c48,50
< // #if !defined(WOLFSSL_MISC_INCLUDED) && !defined(NO_INLINE)
< //     #error misc.c does not need to be compiled when not defined NO_INLINE
< // #endif
---
> #if !defined(WOLFSSL_MISC_INCLUDED) && !defined(NO_INLINE)
>     #error misc.c does not need to be compiled when not defined NO_INLINE
> #endif


$ diff include/wolfssl/wolfcrypt/settings.h include/wolfssl/wolfcrypt/settings.h.0 
34,35d33
< #define WOLFSSL_USER_SETTINGS
< 
```

=========================

## Compiling

1. CD to the correct folder
```bash
cd ESP8266-HomeKit
(cd ../third_party/ ; ./make_lib.sh hkc );./gen_misc.sh
```
2. If you want to skip building hkc lib, just use
```
./gen_misc.sh
```

## Flashing:

```bash
../../esptool/esptool.py --baud 230400 -p /dev/cu.usbserial-AH12345H write_flash 0x00000 ../bin/eagle.flash.bin 0x14000 ../bin/eagle.irom0text.bin
```

### Usage:

- The code writes clients keys to sector 0x13000
- After boot, if the device is not yet paired, an srp-key is calculated in about 25 seconds
- After that the server starts and mulicastdns starts to advertize
- The default pincode is `031-45-154`

Enjoy,
HacK