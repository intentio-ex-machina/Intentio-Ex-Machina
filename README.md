SEIntentFirewall
================

Overview
--------

SEIntentFirewall is a project to replace the already existing intent firewall in Android with a better one.

Installation
------------

The SEIntentFirewall project is currently intended for Android version: 5.0.2_r1.

To install the SEIntentFirewall, replace the java files in your Android framework source with the files included
in this repo:

IntentFirewall.java: `./frameworks/base/services/core/java/com/android/server/firewall/IntentFirewall.java`

ActivityManagerService.java: `./frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java`

ActivityStackSupervisor.java: `./frameworks/base/services/core/java/com/android/server/am/ActivityStackSupervisor.java`

ActiveServices.java: `./frameworks/base/services/core/java/com/android/server/am/ActiveServices.java`

User Firewall
-------------

A user application can become part of the firewall by creating a file named `uf.config` in the
same directory which contains the rule XML files containing the application's firewall
service component name.

Filter Scheme
-------------

Mandatory access control (MAC) rules can be defined by placing an XML file containing the rules into the intent
firewall directory (default /data/system/ifw). The rule files follow this scheme:

    <rules>
    
      <activity block="[true/false]" log="[true/false]" >
        
        <intent-filter >
          <path literal="[literal]" prefix="[prefix]" sglob="[sglob]" />
          <auth host="[host]" port="[port]" />
          <ssp literal="[literal]" prefix="[prefix]" sglob="[sglob]" />
          <scheme name="[name]" />
          <type name="[name]" />
          <cat name="[category]" />
          <action name="[action]" />
        </intent-filter>
        
        <component-filter name="[receiving component]" />

        <user-id sender="[userid]" />
      
        <package-filter sender="[package or *]" receiver="[package or *]" />
        
        <data contains="[string]" />

        <extra type="[int|float|string]" value="[value]" />
        
      </activity>

      <service block="[true/false]" log="[true/false]" >
        
        <intent-filter >
          <path literal="[literal]" prefix="[prefix]" sglob="[sglob]" />
          <auth host="[host]" port="[port]" />
          <ssp literal="[literal]" prefix="[prefix]" sglob="[sglob]" />
          <scheme name="[name]" />
          <type name="[name]" />
          <cat name="[category]" />
          <action name="[action]" />
        </intent-filter>
        
        <component-filter name="[receiving component]" />

        <user-id sender="[userid]" />

        <package-filter sender="[package or *]" receiver="[package or *]" />
        
        <data contains="[string]" />

        <extra type="[int|float|string]" value="[value]" />
        
      </service>
      
    </rules>
