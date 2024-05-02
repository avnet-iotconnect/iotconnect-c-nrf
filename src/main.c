/********************************************************************************************
  SDK for IoTConnect
  
  This IoTConnect SDK will help you to update your Sensors data on IoTConnect cloud(Azure)
  In this example file Humidity, Temperature and Gyroscope(x,y,z) random data published on our cloud at real time

  For run this example you have to include/import "IoTConnect.cpp" or "IoTConnect.h"
  you will need wifi connection for publishing data to IoTCOnnect ..
  For the secure MQTT connection here we are using "X.509 certificats" 
  
  for more help and informationvisit https://help.iotconnect.io SDK section

    modified 27/01/2024
********************************************************************************************/

/********************************************************************************************
Hope you have installed the node SDK as guided on SDK documentation. 
********************************************************************************************/

// Firmware New 3.2


#include "IoTConnect_Config.h"
#include "main.h"

/* Initialize AT communications */
int at_comms_init(void)
{

    int err;
	err = nrf_modem_lib_init();
	if (err) {
		printk("Modem library initialization failed, error: %d\n", err);
		return 0;
	}
}


void main(void)
{  
    int err, count=0;  
    
    err = at_comms_init();
    if (err) 
    {
	    return ;
	}

    err = provision_certificates();
    if (err) 
    {
	    return ;
	}

    printk("Waiting for network.. \n");

    err = lte_lc_init_and_connect();
    if (err == 0) 
    {
        printk("LTE initialization and connection successful\n");
    } 
    else 
    {
        printk("LTE initialization and connection failed with error code: %d\n", err);
        if (err == -EFAULT) 
        {
            printk("Error: AT command failed\n");
        } 
        else if (err == -ETIMEDOUT) 
        {
            printk("Error: Connection attempt timed out\n");
        } 
        else if (err == -EINPROGRESS) 
        {
            printk("Error: Connection establishment already in progress\n");
        } 
        else 
        {
            printk("Unknown error\n");
        }
    }


    printk("OK\n");


    /********************************************************************************************
    ## Prerequisite params to run this sampel code input in IoTConnect_config.h

    - IOTCONNECT_DEVICE_CP_ID              :: It need to get from the IoTConnect platform. 
    - IOTCONNECT_DEVICE_UNIQUE_ID          :: Its device ID which register on IotConnect platform and also its status has Active and Acquired
    - IOTCONNECT_DEVICE_ENV                :: You need to pass respective environment of IoTConnecct platform
    Note : 
    ********************************************************************************************/
    k_msleep(2000);

    err = IoTConnect_Init(IOTCONNECT_DEVICE_CP_ID, IOTCONNECT_DEVICE_UNIQUE_ID, IOTCONNECT_DEVICE_ENV, Device_CallBack, Twin_CallBack);

    if (err) 
    {
        printk("Failed to Init IoTConnect SDK\n");
        return ;
	}

    printk("Init IoTConnect SDK SUCCESS\n");

    /********************************************************************************************
    Type    : Public Method "IoTConnect_Connect()"
    Usage   : To connect with IoTConnect MQTT broker
    ********************************************************************************************/
    reinit:
        if(IoTConnect_Connect() != 0)
        {
            printk("Error : IoTConnect_Connect Fail\n");
        }

    /********************************************************************************************
    Type    : Public Method "getAllTwins()"
    Usage   : To get all the twin properies Desired and Reported
    Output  : All twin property will receive in above callback function "twinUpdateCallback()"
    ********************************************************************************************/
    //getAllTwins()


    while(count < 1000)
    {

        if(MQTT_Status() == 0)
        {
            // all sensors data will be formed in JSON format and will be publied by SendData() function 
            Attribute_json_Data = Sensor_data();

            /********************************************************************************************
            Type    : Public Method "sendData()"
            Usage   : To publish the D2C data 
            Output  : 
            Input   : Predefined data object 
            ********************************************************************************************/
            if(SendData(Attribute_json_Data) != 0)
            {
                printk("Error : Attribute_json_Data Send Data\n");
            }

        }
        else
        {
            printk("MQTT Connection Failed\n");
            //TODO: Break the loop, wait for internet connectivity, start form reinit goto handler
            printk("Waiting for 5 sec\n Trying to reinit IotConnect MQTT Connection\n");
            k_msleep(5000);
            goto reinit;
        }

		k_msleep(15000);
    }


    /********************************************************************************************
    Type    : Public Method "IoTConnect_Abort()"
    Usage   : Disconnect the device from cloud
    Output  : 
    Input   : 
    Note : It will disconnect the device after defined time 
    ********************************************************************************************/ 
    err = IoTConnect_Abort();
    if (err)
    {
        printk("Failed to Abort IoTConnect SDK\n");
        return ;
    }
}


/*******************************************************************************************
Type    : Callback Function "TwinUpdateCallback()"
Usage   : Manage twin properties as per business logic to update the twin reported property
Output  : Receive twin properties Desired, Reported
Input   : 
********************************************************************************************/
void Twin_CallBack(char *topic, char *payload)
{      
    char *key = NULL, *value = NULL;
    int device_type;
    printk("Twin_msg payload is >>  %s\n", payload);
    
    cJSON *root = cJSON_Parse(payload);        
    cJSON *D = cJSON_GetObjectItem(root, "desired");
    if(D) 
    {
        cJSON *device = D->child;
        while (device) 
        {
            if (!strcmp(device->string, "$version")) 
            {}
            else 
            {
                key = device->string;
                device_type = device->type;
                if(device_type == 8)
                { 
                    int  int_val;
                    double diff, flot_val;
                    flot_val = (cJSON_GetObjectItem(D, key))->valuedouble;
                    int_val = flot_val;
                    diff = flot_val - int_val;
                    if (diff > 0) {} 
                    if (diff <= 0)
                    {
                        printk("int value: %d\n", (cJSON_GetObjectItem(D, key))->valueint);
                        UpdateTwin_Int(key, int_val);
                    }
                }
                if (device_type == 16)
                {
                    value = (cJSON_GetObjectItem(D, key))->valuestring;
                    printk("string value: %s\n", value);
                    UpdateTwin(key,value);
                }
                if (device_type == 4 || device_type == 64)
                {
                    printk("Removed twin %s has value NULL\n", key);
                }
            }
            device = device->next;
        }		
    }
}


/********************************************************************************************
Type    : Callback Function "Device_CallBack()"
Usage   : Firmware will receive commands from cloud. You can manage your business logic as per received command.
Output  : Receive device command, firmware command and other device initialize error response
Input   :  
********************************************************************************************/
void Device_CallBack(char *topic, char *payload)
{      
    
    cJSON *Ack_Json, *sub_value, *in_url;
    int Status = 0,magType=0;
    char *cmd_ackID, *Cmd_value, *Ack_Json_Data, *cmd_Uni="";
    char data_to_print[120+1];
    char *find;
    int len;
    

    find = strstr(payload, "guid");
    len = (find-payload) - 6;
    if (len>120)
        len = 120;
    memset(data_to_print, 0, sizeof(data_to_print));
    memcpy(&data_to_print, &payload[4], len);
    printk("Cmd_msg >> %s\n", &data_to_print);   

    cJSON *root = cJSON_Parse(payload);
    cmd_ackID = (cJSON_GetObjectItem(root, "ackId"))->valuestring;
    Cmd_value = (cJSON_GetObjectItem(root, "cmdType"))->valuestring;

    if( !strcmp(Cmd_value,"0x16"))
	{
		sub_value = cJSON_GetObjectItem(root,"command");
		int CMD = sub_value->valueint;
		if(CMD == 1){
			printk("\r\n\t ** Device Connected ** \n");
		} 
		else if(CMD == 0) 
		{
			printk("\r\n\t ** Device Disconnected ** \n");
		}
		return;
    }

    if( !strcmp(Cmd_value,"0x01") )
	{
		Status = 6; magType = 5;
	}
    else if( !strcmp(Cmd_value,"0x02") ) 
	{
        Status = 7; magType = 11;
    	sub_value = cJSON_GetObjectItem(root,"urls");
		if(cJSON_IsArray(sub_value)){
            in_url = cJSON_GetArrayItem(sub_value, 0);
            sub_value = cJSON_GetObjectItem(in_url, "uniqueId");
            if(cJSON_IsString(sub_value))
			cmd_Uni = sub_value->valuestring;
		}
    } else { }

    Ack_Json = cJSON_CreateObject();
    if (Ack_Json == NULL)
	{
        printk("Unable to allocate Ack_Json Object in Device_CallBack\n");
        return ;    
    }
    cJSON_AddStringToObject(Ack_Json, "ackId",cmd_ackID);
    cJSON_AddStringToObject(Ack_Json, "msg","");
    //cJSON_AddStringToObject(Ack_Json, "childId",cmd_Uni);
    cJSON_AddNumberToObject(Ack_Json, "st", Status);

    Ack_Json_Data = cJSON_PrintUnformatted(Ack_Json);
    
    /*
    Type    : Public Method "sendAck()"
    Usage   : Send firmware command received acknowledgement to cloud
      - status Type
		st = 6; // Device command Ack status 
		st = 7; // firmware OTA command Ack status 
        st = 4; // Failed Ack
      - Message Type
		msgType = 5; // for "0x01" device command 
        msgType = 11; // for "0x02" Firmware command
    */  
    SendAck(Ack_Json_Data, magType);
    cJSON_Delete(Ack_Json);
}


// All Sensor telemetry data formation here in JSON 
char *Sensor_data(void)
{

    cJSON *Attribute_json = NULL;
    cJSON *Device_data1 = NULL;
    cJSON *Data = NULL, *Data1= NULL;

    Attribute_json = cJSON_CreateArray();
    if (Attribute_json == NULL)
    {
        printk("Unable to allocate Attribute_json Object\n");
        return NULL;    
    }

    cJSON_AddItemToArray(Attribute_json, Device_data1 = cJSON_CreateObject());
    cJSON_AddStringToObject(Device_data1, "uniqueId",IOTCONNECT_DEVICE_UNIQUE_ID);
    cJSON_AddStringToObject(Device_data1, "time", Get_Time());
    cJSON_AddItemToObject(Device_data1, "data", Data = cJSON_CreateObject());
    cJSON_AddNumberToObject(Data,"Humidity",30);
    cJSON_AddNumberToObject(Data, "Temperature",18);
    cJSON_AddItemToObject(Data, "Gyroscope", Data1 = cJSON_CreateObject());
    cJSON_AddNumberToObject(Data1,"X",128);
    cJSON_AddNumberToObject(Data1,"Y",148);
    cJSON_AddNumberToObject(Data1,"Z",318);
    
    char *msg = cJSON_PrintUnformatted(Attribute_json);
    cJSON_Delete(Attribute_json);
    return  msg;
}
