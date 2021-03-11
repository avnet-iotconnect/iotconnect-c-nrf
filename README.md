## IOT Connect SDK for nRF: version 2.2.0

Prerequisite tools:

> Install nRF9160 SDK with 1.2.0 version and complete Getting Started with nRF9160 DK.
	(https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrf/index.html)

Installation :
> For making new application, create a folder in nrf-sample folder and name is IoTConnect where you installed nRFConnet SDK .(path lool like  ....Nordic\ncs\nrf\samples\nrf9160\IoTConnect ).
> Now unzip the nRF9160_DK SDK which you get from our IoTConnect portal
>We have main.c and main.h file in nRF9160-DK\src with IoTConnect_config.h ( you need to input CPID and deviceID and env here in  IoTConnect_config.h)
>In the other folder nRF9160-DK\IoTConnect\cert we have a certificate.h in here you have to put your device certificate 

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

---- Already add in here -------
-------Do Not Change -----------

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
