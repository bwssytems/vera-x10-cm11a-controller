# vera-x10-cm11a-controller
Creates a vera controller that child switches are then added to it.

I've been trying the different plugins for X10 control. I have used the mochad plugin and that works very well, you just need to have another server to run mochad on. I wanted to use the direct connection for the CM11 through a USB to serial adapter and have tried brucehvn's X10 plugin on the forum.micasaverde.com and that works pretty well. There are issues with target updates on dimmables for on/off with third party applications.

So, I looked at merging these two projects as I like the simplicity for the mochad plugin and all the work that was put into brucehvn's plugin for CM11 handling and created a streamlined X10 plugin. So this is basically a mashup between the two and those devs earn the credit for all of this as they did all the hard work.

Installation instructions
-----
These instructions are based on UI5.

1) Upload the files from the zip archive via Apps->Develop Apps->Luup Files.

2) Go to the "Create Device" tab. Fill in these fields:
```
Description: a name, type whatever you want to call the CM11 PLI.  Something like "X10 CM11A PLI" or whatever you like.
UpnpDevFilename: D_X10CM11a.xml
UpnpImplFilename: I_X10CM11a.xml
Put in a room if you like (not required)
```
Press the "Create Device" button.  You should get a message about the device being created.

3) Plug your CM11 a into vera via a USB to serial adapter and reboot Vera.  If you need help getting Vera to recognize your USB to serial adapter, see this thread:
http://forum.micasaverde.com/index.php/topic,1471.0.html

When you see your USB to serial device in the configuration screen, set the following parameters:
```
Baud Rate: 4800
Parity: None
Data Bits: 8
Stop Bits: 1
```
In the "Used By Device" dropdown, find the X10 PLI device you created in step 2 and select that.

4) You are now ready to create devices for the CM11 to interact with.

5) in the devices tab find the CM11 and Click the little wrench in the upper right hand corner of the device.
Go to the "Advanced" tab and scroll down to the "Variables" section.
Fill in the following variables:
```
BinaryModules: a comma separated list of house/unit codes for any appliance modules you may have. For example: "A1,D2"
DimableModules: a comma separated list of house/unit codes, but for *old style* dimmable modules.
SoftstartModules: a comma separated list of house/unit codes, but for newer dimmable modules like any recently produced LM465s.
MotionSensors: a comma separated list of house/unit codes for any motion sensors you may have. Don't forget that X10 outside motion sensors (like the EagleEye MS14A and the ActiveEye MS16A) have a photosensor that will return a code for transitions to night/day. These alerts occur at a unit code one above the currently set unit code. This means that a motion sensor set to M1 will alert on M1 when there is motion and M2 for day / night.
```
6) make sure you reload your vera so that all the dvices are created.

7) test out your new devices and you should be good to go!
