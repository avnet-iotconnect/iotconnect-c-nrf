# Softweb Solutions Inc
## IOT Connect SDK : Software Development Kit 3.1

Prerequisite tools:

1.	Install nRF9160 nrf SDK with 2.5.0 version along with modem firmware version 1.3.5 and complete Getting Started with nRF9160 DK.
	- Reference link to install (https://developer.nordicsemi.com/nRF_Connect_SDK/doc/2.5.0/nrf/installation.html)

Installation :
1. 	For making new application, create a folder in nrf-sample folder and name is "IoTConnect" where you installed nRFConnet SDK.
	- Path to create folder : e.g.(C:\nordic\v2.5.0\nrf\samples\).
2. 	Now unzip the "iotconnect-C-sdk-nRF-3.1.zip" SDK which you can download from our IoTConnect help portal.
3.	We have "main.c" and "main.h" file in "nRF9160-DK\src" with "IoTConnect_config.h".
	- you need to input "uniqueIdID", "CPID" and "env" in IoTConnect_config.h file. You can see more in below section title with "Prerequisite input data"
4.	In the other folder "nRF9160-DK\IoTConnect\cert" we have a "certificate.h" in here you have to put your device certificate. If uding x.509 CA based authentcation. 

```C-SDK
#define CLOUD_CLIENT_PRIVATE_KEY \
"-----BEGIN RSA PRIVATE KEY-----\n"
----------------------------------
----------------------------------
"-----END RSA PRIVATE KEY-----\n"

#define CLOUD_CLIENT_PUBLIC_CERTIFICATE \
"-----BEGIN CERTIFICATE-----\n"
----------------------------------
----------------------------------
"-----END CERTIFICATE-----\n"

#define CLOUD_CA_CERTIFICATE \
"-----BEGIN CERTIFICATE-----\n" \
----------------------------------
----------------------------------
"-----END CERTIFICATE-----\n"
```

Import library in main file 
```C-SDK

#include "IoTConnect_Config.h"
#include "main.h"
```

Prerequisite input data *
```C-SDK
#define IOTCONNECT_DEVICE_UNIQUE_ID    "from IoTConnect portal"
#define IOTCONNECT_DEVICE_CP_ID        "from IoTConnect portal"
#define IOTCONNECT_DEVICE_ENV          "from IoTConnect portal"
```

To get the device information and connect to the device
```C-SDK
IoTConnect_init(IOTCONNECT_DEVICE_CP_ID, IOTCONNECT_DEVICE_UNIQUE_ID, IOTCONNECT_DEVICE_ENV, Device_CallBack, Twin_CallBack);
```

To Connect mqtt client with IoTConnect cloud 
```C-SDK
IoTConnect_connect();
```

To receive the All twins from Cloud to Device(C2D)
```C-SDK
getAllTwins();
```

Data input format
```C-SDK
// All telemetry data in json formation here
char *Sensor_data(void){
    cJSON *Attribute_json = NULL;
    cJSON *Device_data1 = NULL;
    cJSON *Data = NULL, *Data1= NULL;

    Attribute_json = cJSON_CreateArray();
    if (Attribute_json == NULL){
        printk("Unable to allocate Attribute_json Object\n");
        return ;    
      }
      cJSON_AddItemToArray(Attribute_json, Device_data1 = cJSON_CreateObject());
      cJSON_AddStringToObject(Device_data1, "uniqueId",uniqueId);
      cJSON_AddStringToObject(Device_data1, "time", Get_Time());
      cJSON_AddItemToObject(Device_data1, "data", Data = cJSON_CreateObject());
      cJSON_AddStringToObject(Data,"Humidity", "87.33" );
      cJSON_AddNumberToObject(Data, "Temperature",  18.26);
      cJSON_AddItemToObject(Data, "Gyroscope", Data1 = cJSON_CreateObject());
      cJSON_AddNumberToObject(Data1, "x",  128);
      cJSON_AddStringToObject(Data1, "y", "Black" );
      cJSON_AddNumberToObject(Data1, "z",  318);
      
      char *msg = cJSON_PrintUnformatted(Attribute_json);
      cJSON_Delete(Attribute_json);
      return  msg;
}
```

To send the data from Device To Cloud(D2C)
```C-SDK
SendData(Attribute_json_Data);
```

To receive the command from Cloud to Device(C2D) with ACK to cloud
```C-SDK
void Device_CallBack(char *topic, char *payload) {      
    
    cJSON *Ack_Json;
    int Status = 0,mt=0;
    char *cmd_ackID, *Cmd_value, *Ack_Json_Data;
    printk("\n Cmd_msg >>  %s",payload);   
}
	
```

To receive the twin from Cloud to Device(C2D)
```C-SDK
char *key = "twin01", *value = NULL;
// this function will Give you TwinCallBack payload uncomment that UpdateTwin function for D2C
void Twin_CallBack(char *topic, char *payload) {      
    printk("\n Twin_msg >>  %s",payload);  
	
}

```
To Stoped the IoTConnect SDK
```C-SDK
// After this SDK will Stop you need to reboot your device or SDK
IoTConnect_abort();   
```