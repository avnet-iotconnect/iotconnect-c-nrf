#ifndef MAIN_H
#define MAIN_H

#include "../IoTConnect/src/IoTConnectSDK.h"
char *Attribute_json_Data = " ";
char *Sensor_data(void);


char *Get_Time(void);
int at_comms_init(void);

int provision_certificates(void);

#endif /* MAIN_H */



