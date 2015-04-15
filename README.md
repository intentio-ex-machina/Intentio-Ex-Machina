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

`IntentFirewall.java`: `./frameworks/base/services/core/java/com/android/server/firewall/IntentFirewall.java`
`ActivityStackSupervisor.java`: `./frameworks/base/services/core/java/com/android/server/am/ActivityStackSupervisor.java`
