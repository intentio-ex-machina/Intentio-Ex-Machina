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

ActivityStackSupervisor.java: `./frameworks/base/services/core/java/com/android/server/am/ActivityStackSupervisor.java`

ActiveServices.java: `./frameworks/base/services/core/java/com/android/server/am/ActiveServices.java`

Filter Scheme
-------------

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

        <package-filter sender="[package or *]" receiver="[package or *]" />
        
        <data contains="[string]" />

        <extra type="[int|float|string]" value="[value]" />
        
      </service>
      
    </rules>
