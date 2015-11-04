/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Modified by Carter Yagemann for SEIntent Firewall project.
 * Copyright (C) 2015 All rights reserved.
 */

package com.android.server.firewall;

import android.app.AppGlobals;
import android.app.ApplicationThreadNative;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.ServiceConnection;
import android.content.IIntentReceiver;
import android.app.IApplicationThread;
import android.app.IServiceConnection;
import android.app.ProfilerInfo;
import android.content.pm.IPackageManager;
import android.content.pm.PackageManager;
import android.os.Environment;
import android.os.FileObserver;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.os.UserHandle;
import android.os.Bundle;
import android.util.ArrayMap;
import android.util.Slog;
import android.util.Xml;
import com.android.internal.util.ArrayUtils;
import com.android.internal.util.XmlUtils;
import com.android.server.EventLogTags;
import com.android.server.IntentResolver;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

public class IntentFirewall {
    static final String TAG = "IntentFirewall";

    // e.g. /data/system/ifw or /data/secure/system/ifw
    private static final File RULES_DIR = new File(Environment.getSystemSecureDirectory(), "ifw");

    private static final int LOG_PACKAGES_MAX_LENGTH = 150;
    private static final int LOG_PACKAGES_SUFFICIENT_LENGTH = 125;

    private static final String TAG_RULES     = "rules";
    private static final String TAG_ACTIVITY  = "activity";
    private static final String TAG_SERVICE   = "service";
    private static final String TAG_BROADCAST = "broadcast";

    private static final int TYPE_ACTIVITY  = 0;
    private static final int TYPE_BROADCAST = 1;
    private static final int TYPE_SERVICE   = 2;

    private static final int CHECK_INTENT = 1;

    private static final int BLOCK_INTENT   = 0;
    private static final int ALLOW_INTENT   = 1;
    private static final int FORWARD_INTENT = 2;

    private static final String IFW_TOKEN = "INTENT_FIREWALL_TOKEN";
    private static final String IFW_SERVICE_ACTION = "IFW_SERVICE_ACTION";

    private static final int TOKEN_VALID       = 0;
    private static final int TOKEN_NOT_PRESENT = 1;
    private static final int TOKEN_CORRUPT     = 2;

    private static final HashMap<String, FilterFactory> factoryMap;

    private final AMSInterface mAms;

    private final RuleObserver mObserver;

    private FirewallIntentResolver mActivityResolver = new FirewallIntentResolver();
    private FirewallIntentResolver mBroadcastResolver = new FirewallIntentResolver();
    private FirewallIntentResolver mServiceResolver = new FirewallIntentResolver();

    private static boolean forwardUserFirewall = false;
    private static ComponentName mUserFirewall;

    private UFWServiceConnection mUFW_SC = new UFWServiceConnection();
    private Messenger mUFWMessenger = new Messenger(new UFWHandler());
    private Messenger mUFWService;

    static {
        FilterFactory[] factories = new FilterFactory[] {
                AndFilter.FACTORY,
                OrFilter.FACTORY,
                NotFilter.FACTORY,

                StringFilter.ACTION,
                StringFilter.COMPONENT,
                StringFilter.COMPONENT_NAME,
                StringFilter.COMPONENT_PACKAGE,
                StringFilter.DATA,
                StringFilter.HOST,
                StringFilter.MIME_TYPE,
                StringFilter.SCHEME,
                StringFilter.PATH,
                StringFilter.SSP,

                CategoryFilter.FACTORY,
                SenderFilter.FACTORY,
                SenderPackageFilter.FACTORY,
                SenderPermissionFilter.FACTORY,
                PortFilter.FACTORY
        };

        // load factor ~= .75
        factoryMap = new HashMap<String, FilterFactory>(factories.length * 4 / 3);
        for (int i=0; i<factories.length; i++) {
            FilterFactory factory = factories[i];
            factoryMap.put(factory.getTagName(), factory);
        }
    }

    public IntentFirewall(AMSInterface ams, Handler handler) {
        mAms = ams;
        mHandler = new FirewallHandler(handler.getLooper());
        File rulesDir = getRulesDir();
        rulesDir.mkdirs();

        readRulesDir(rulesDir);
        loadUserFirewall(rulesDir);

        mObserver = new RuleObserver(rulesDir);
        mObserver.startWatching();
    }

    /**
     * Given an intent, generates a token.
     */
    private String generateToken() {
        //TODO implement tokenizer
        return "I am not a secure token";
    }

    /**
     * Checks an intent for a token and if it's there, validates it.
     */
    private int validateToken(Intent intent) {
        String token = intent.ifwToken;
        if (token == null) return TOKEN_NOT_PRESENT;
        if (generateToken().equals(token)) return TOKEN_VALID;
        return TOKEN_CORRUPT;
    }

    private void sendActivityToUserFirewall(IApplicationThread caller, String callingPackage,
            Intent intent, String resolvedType, IBinder resultTo, String resultWho, int requestCode,
            int startFlags, Bundle options, int userId) {
        // Tokenize intent
        intent.ifwToken = generateToken();
        // Package bundle
        Bundle data = new Bundle();
        if (caller != null) data.putBinder("caller", caller.asBinder());
        data.putString("callingPackage", callingPackage);
        data.putParcelable("intent", intent);
        data.putInt("intentType", TYPE_ACTIVITY);
        data.putString("resolvedType", resolvedType);
        data.putBinder("resultTo", resultTo);
        data.putString("resultWho", resultWho);
        data.putInt("requestCode", requestCode);
        data.putInt("startFlags", startFlags);
        data.putBundle("options", options);
        data.putInt("userId", userId);
        // Prepare message
        Message msg = Message.obtain(null, CHECK_INTENT);
        msg.setData(data);
        msg.replyTo = mUFWMessenger;
        // Send message
        try {
            mUFWService.send(msg);
        } catch (RemoteException e) {
            Slog.w(TAG, "Failed to send check intent message to user firewall.");
        }
    }

    private void sendServiceToUserFirewall(IApplicationThread caller, IBinder token, Intent service,
            String resolvedType, IServiceConnection connection, int flags, int userId, String action,
            int callerUid, int callerPid, String callerPackage) {
        // Make sure user firewall is bound
        if (mUFWService == null) {
            Slog.w(TAG, "User firewall is enabled, but not bound yet. Dropping service intent.");
            return;
        }
        // Tokenize intent
        service.ifwToken = generateToken();
        // Package bundle
        Bundle data = new Bundle();
        if (caller != null) data.putBinder("caller", caller.asBinder());
        data.putBinder("token", token);
        data.putString(IFW_SERVICE_ACTION, action);
        data.putParcelable("intent", service);
        data.putInt("intentType", TYPE_SERVICE);
        data.putString("resolvedType", resolvedType);
        if (connection != null) data.putBinder("connection", connection.asBinder());
        data.putInt("flags", flags);
        data.putInt("userId", userId);
        data.putString("callingPackage", callerPackage);
        data.putInt("callerUid", callerUid);
        data.putInt("callerPid", callerPid);
        // Prepare message
        Message msg = Message.obtain(null, CHECK_INTENT);
        msg.setData(data);
        msg.replyTo = mUFWMessenger;
        try {
            mUFWService.send(msg);
        } catch (RemoteException e) {
            Slog.w(TAG, "Failed to send check intent message to user firewall.");
            return;
        }
    }

    private void sendBroadcastToUserFirewall(IApplicationThread caller, Intent intent,
            String resolvedType, IIntentReceiver resultTo, int resultCode, String resultData, Bundle map,
            String requiredPermission, int appOp, boolean serialized, boolean sticky, int userId) {
        // Tokenize intent
        intent.ifwToken = generateToken();
        // Package bundle
        Bundle data = new Bundle();
        if (caller != null) data.putBinder("caller", caller.asBinder());
        data.putParcelable("intent", intent);
        data.putInt("intentType", TYPE_BROADCAST);
        data.putString("resolvedType", resolvedType);
        if (resultTo != null) data.putBinder("resultTo", resultTo.asBinder());
        data.putInt("resultCode", resultCode);
        data.putString("resultData", resultData);
        data.putBundle("map", map);
        data.putString("requiredPermission", requiredPermission);
        data.putInt("appOp", appOp);
        data.putBoolean("serialized", serialized);
        data.putBoolean("sticky", sticky);
        data.putInt("userId", userId);
        // Prepare message
        Message msg = Message.obtain(null, CHECK_INTENT);
        msg.setData(data);
        msg.replyTo = mUFWMessenger;
        // Send message
        try {
            mUFWService.send(msg);
        } catch (RemoteException e) {
            Slog.w(TAG, "Failed to send check intent message to user firewall.");
        }
    }

    /**
     * This is called from ActivityManager to check if a start activity intent should be allowed.
     * It is assumed the caller is already holding the global ActivityManagerService lock.
     */
    public boolean checkStartActivity(IApplicationThread caller, Intent intent, int callerUid,
            int callerPid, String resolvedType, ApplicationInfo resolvedApp,
            String callerPackage, int userId, int requestCode, IBinder resultTo,
            String resultWho, int startFlags, Bundle options) {
        int res = checkIntent(mActivityResolver, intent.getComponent(), TYPE_ACTIVITY, intent,
                callerUid, callerPid, resolvedType, resolvedApp.uid, callerPackage, userId, requestCode);
        switch(res) {
            case ALLOW_INTENT:
                return true;
            case BLOCK_INTENT:
                return false;
            case FORWARD_INTENT:
                sendActivityToUserFirewall(caller, callerPackage, intent, resolvedType, resultTo, resultWho,
                    requestCode, startFlags, options, userId);
                return false;
        }
        return false;
    }

    public int checkService(IApplicationThread caller, IBinder token, IServiceConnection connection,
            ComponentName resolvedService, Intent intent, int callerUid, int callerPid, String resolvedType,
            ApplicationInfo resolvedApp, String callerPackage, int flags, int userId, String action) {
        int res = checkIntent(mServiceResolver, resolvedService, TYPE_SERVICE, intent, callerUid,
                callerPid, resolvedType, resolvedApp.uid, callerPackage, userId, -1);
        switch(res) {
            case ALLOW_INTENT:
                return 0;
            case BLOCK_INTENT:
                return 1;
            case FORWARD_INTENT:
                sendServiceToUserFirewall(caller, token, intent, resolvedType, connection, flags, userId,
                    action, callerUid, callerPid, callerPackage);
                return 2;
        }
        return 1;
    }

    public boolean checkBroadcast(IApplicationThread caller, Intent intent, int callerUid, int callerPid,
            String resolvedType, IIntentReceiver resultTo, int resultCode, String resultData, Bundle map,
            String requiredPermission, int appOp, boolean serialized, boolean sticky, int receivingUid, int userId) {
        int res = checkIntent(mBroadcastResolver, intent.getComponent(), TYPE_BROADCAST, intent,
                callerUid, callerPid, resolvedType, receivingUid, null, 0, -1);
        switch(res) {
            case ALLOW_INTENT:
                return true;
            case BLOCK_INTENT:
                return false;
            case FORWARD_INTENT:
                sendBroadcastToUserFirewall(caller, intent, resolvedType, resultTo, resultCode, resultData,
                    map, requiredPermission, appOp, serialized, sticky, userId);
                return false;
        }
        return false;
    }

    /**
     * This method performs the bulk of the intent checking. It returns an int to advise the caller to either
     * block the intent, allow the intent, or forward the intent to the user firewall.
     */
    public int checkIntent(FirewallIntentResolver resolver, ComponentName resolvedComponent,
            int intentType, Intent intent, int callerUid, int callerPid, String resolvedType,
            int receivingUid, String callerPackage, int userId, int requestCode) {

        // Mandatory Access Control
        boolean mac = checkMAC(resolver, resolvedComponent, intentType, intent, callerUid,
            callerPid, resolvedType, receivingUid, callerPackage, userId);
        // If it failed the MAC, get rid of it!
        if (!mac) return BLOCK_INTENT;

        // If there isn't a userfirewall, then MAC is all we check
        if (mUFWService == null) return ALLOW_INTENT;

        // At this point, the intent has passed MAC and there is a user firewall. If it is a system
        // intent, we'll allow it because we don't want the user firewall to be able to block intents which
        // are critical to the system's stability.
        if (!UserHandle.isApp(callerUid)) return ALLOW_INTENT;

        // We also allow the intent to bypass the user firewall if it is an intra-app intent. This is because
        // the user firewall's purpose is to inspect intents which travel between apps, not intents being
        // sent and received from within the same app.
        if (callerPackage != null && resolvedComponent != null)
            if (callerPackage.equals(resolvedComponent.getPackageName()))
                return ALLOW_INTENT;

        // If it isn't sent by system, then it was sent by a normal app. If it has a valid token, then it
        // has already been through the user firewall and we can allow it. If it has no token, we'll advise
        // the caller to tokenize and forward it. If there is a token but it's invalid, something bad has
        // happened and this intent needs to be blocked.
        int tokenCheck = validateToken(intent);
        if (tokenCheck == TOKEN_VALID) return ALLOW_INTENT;
        if (tokenCheck == TOKEN_NOT_PRESENT) return FORWARD_INTENT;
        // Token was corrupt. This is very bad.
        Slog.w(TAG, "Blocking corrupted token from " + callerPackage);
        return BLOCK_INTENT;
    }

    /**
     * Checks intent against intent firewall's rules to determine if the intent should be
     * allowed and/or logged. Since these rules come from the intent firewall's rules list,
     * this is mandatory access control.
     *
     * Returns true if the intent should be allowed.
     */
    private boolean checkMAC(FirewallIntentResolver resolver, ComponentName resolvedComponent,
            int intentType, Intent intent, int callerUid, int callerPid, String resolvedType,
            int receivingUid, String callerPackage, int userId) {

        boolean log = false;
        boolean block = false;

        // For the first pass, find all the rules that have at least one intent-filter or
        // component-filter that matches this intent
        List<Rule> candidateRules;
        candidateRules = resolver.queryIntent(intent, resolvedType, false, 0);
        if (candidateRules == null) {
            candidateRules = new ArrayList<Rule>();
        }
        resolver.queryByComponent(resolvedComponent, candidateRules);

        // Check for userId Rules
        if (userId > 0)
            resolver.queryByUserId(Integer.toString(userId), candidateRules);

        // Check for data rules
        resolver.queryByData(intent.getDataString(), candidateRules);

        // Check for extra rules
        resolver.queryByExtra(intent, candidateRules);

        // Check for PackagePair Rules
        int packagePairMatches = 0;
        // First check for explicit matches
        if (callerPackage != null && resolvedComponent.getPackageName() != null) {
            packagePairMatches =
                resolver.queryByPackagePair(new PackagePair(callerPackage, resolvedComponent.getPackageName()), candidateRules);
            // If there are no explicit matches, check for wildcard matches
            if (packagePairMatches == 0)
                resolver.queryByPackagePair(new PackagePair(callerPackage, "*"), candidateRules);
        }

        // For the second pass, try to match the potentially more specific conditions in each
        // rule against the intent
        for (int i=0; i<candidateRules.size(); i++) {
            Rule rule = candidateRules.get(i);
            if (rule.matches(this, resolvedComponent, intent, callerUid, callerPid, resolvedType,
                    receivingUid)) {
                block |= rule.getBlock();
                log |= rule.getLog();

                // if we've already determined that we should both block and log, there's no need
                // to continue trying rules
                if (block && log) {
                    break;
                }
            }
        }

        if (log) {
            logIntent(intentType, intent, callerUid, resolvedType);
        }

        return !block;
    }

    private static void logIntent(int intentType, Intent intent, int callerUid,
            String resolvedType) {
        // The component shouldn't be null, but let's double check just to be safe
        ComponentName cn = intent.getComponent();
        String shortComponent = null;
        if (cn != null) {
            shortComponent = cn.flattenToShortString();
        }

        String callerPackages = null;
        int callerPackageCount = 0;
        IPackageManager pm = AppGlobals.getPackageManager();
        if (pm != null) {
            try {
                String[] callerPackagesArray = pm.getPackagesForUid(callerUid);
                if (callerPackagesArray != null) {
                    callerPackageCount = callerPackagesArray.length;
                    callerPackages = joinPackages(callerPackagesArray);
                }
            } catch (RemoteException ex) {
                Slog.e(TAG, "Remote exception while retrieving packages", ex);
            }
        }

        EventLogTags.writeIfwIntentMatched(intentType, shortComponent, callerUid,
                callerPackageCount, callerPackages, intent.getAction(), resolvedType,
                intent.getDataString(), intent.getFlags());
    }

    /**
     * Joins a list of package names such that the resulting string is no more than
     * LOG_PACKAGES_MAX_LENGTH.
     *
     * Only full package names will be added to the result, unless every package is longer than the
     * limit, in which case one of the packages will be truncated and added. In this case, an
     * additional '-' character will be added to the end of the string, to denote the truncation.
     *
     * If it encounters a package that won't fit in the remaining space, it will continue on to the
     * next package, unless the total length of the built string so far is greater than
     * LOG_PACKAGES_SUFFICIENT_LENGTH, in which case it will stop and return what it has.
     */
    private static String joinPackages(String[] packages) {
        boolean first = true;
        StringBuilder sb = new StringBuilder();
        for (int i=0; i<packages.length; i++) {
            String pkg = packages[i];

            // + 1 length for the comma. This logic technically isn't correct for the first entry,
            // but it's not critical.
            if (sb.length() + pkg.length() + 1 < LOG_PACKAGES_MAX_LENGTH) {
                if (!first) {
                    sb.append(',');
                } else {
                    first = false;
                }
                sb.append(pkg);
            } else if (sb.length() >= LOG_PACKAGES_SUFFICIENT_LENGTH) {
                return sb.toString();
            }
        }
        if (sb.length() == 0 && packages.length > 0) {
            String pkg = packages[0];
            // truncating from the end - the last part of the package name is more likely to be
            // interesting/unique
            return pkg.substring(pkg.length() - LOG_PACKAGES_MAX_LENGTH + 1) + '-';
        }
        return null;
    }

    public static File getRulesDir() {
        return RULES_DIR;
    }

    /**
     * Looks for a file named uf.config and tries to unflatten it into a ComponentName for the
     * user firewall service. The intent firewall will forward non-system access control decisions
     * to this service component.
     */
    private void loadUserFirewall(File rulesDir) {
        // If there currently is a user firewall, make sure we're unbound from it.
        if (mUserFirewall != null) {
            try {
                mAms.getSystemContext().unbindService(mUFW_SC);
            } catch (Exception e) {
                Slog.w(TAG, "Tried to unbind from user firewall, but failed.");
            }
        }
        // Discard old user firewall settings
        mUserFirewall = null;
        forwardUserFirewall = false;

        File[] files = rulesDir.listFiles();
        for (int i=0; i<files.length; i++) {
            File file = files[i];
            if (file.getName().endsWith("uf.config")) {
                FileInputStream fis;
                BufferedReader br;
                try {
                    fis = new FileInputStream(file);
                    br = new BufferedReader(new InputStreamReader(fis));
                } catch (Exception ex) {
                    Slog.e(TAG, "Failed to open file: " + file.getName());
                    continue;
                }
                try {
                    String compString = br.readLine();
                    br.close();
                    mUserFirewall = ComponentName.unflattenFromString(compString);
                    Slog.i(TAG, "Enabled user firwall: " + mUserFirewall.toShortString());
                    // There should only be one uf.config
                    break;
                } catch (Exception ex) {
                    Slog.e(TAG, "Failed to unflatten user firewall component.");
                    continue;
                }
            }
        }

        if (mUserFirewall == null) {
            Slog.i(TAG, "Disabled user firewall.");
        } else {
            bindToUFW();
        }
    }

    /**
     * Attempt to bind to the user firewall.
     */
    private void bindToUFW() {
        if (mUserFirewall != null) {
            try {
                Intent service = new Intent();
                service.setComponent(mUserFirewall);
                mAms.getSystemContext().bindService(service, mUFW_SC, Context.BIND_AUTO_CREATE);
                Slog.i(TAG, "Sent bind request to user firewall.");
            } catch (Exception e) {
                Slog.w(TAG, "Unable to find user firewall, retrying later...");
                mHandler.sendEmptyMessageDelayed(2, 5000);
            }
        }
    }

    /**
     * Reads rules from all xml files (*.xml) in the given directory, and replaces our set of rules
     * with the newly read rules.
     *
     * We only check for files ending in ".xml", to allow for temporary files that are atomically
     * renamed to .xml
     *
     * All calls to this method from the file observer come through a handler and are inherently
     * serialized
     */
    private void readRulesDir(File rulesDir) {
        FirewallIntentResolver[] resolvers = new FirewallIntentResolver[3];
        for (int i=0; i<resolvers.length; i++) {
            resolvers[i] = new FirewallIntentResolver();
        }

        File[] files = rulesDir.listFiles();
        if (files != null) {
            for (int i=0; i<files.length; i++) {
                File file = files[i];

                if (file.getName().endsWith(".xml")) {
                    readRules(file, resolvers);
                }
            }
        }

        Slog.i(TAG, "Read new rules (A:" + resolvers[TYPE_ACTIVITY].getRulesCount() +
                " B:" + resolvers[TYPE_BROADCAST].getRulesCount() +
                " S:" + resolvers[TYPE_SERVICE].getRulesCount() + ")");

        synchronized (mAms.getAMSLock()) {
            mActivityResolver = resolvers[TYPE_ACTIVITY];
            mBroadcastResolver = resolvers[TYPE_BROADCAST];
            mServiceResolver = resolvers[TYPE_SERVICE];
        }
    }

    /**
     * Reads rules from the given file and add them to the given resolvers
     */
    private void readRules(File rulesFile, FirewallIntentResolver[] resolvers) {
        // some temporary lists to hold the rules while we parse the xml file, so that we can
        // add the rules all at once, after we know there weren't any major structural problems
        // with the xml file
        List<List<Rule>> rulesByType = new ArrayList<List<Rule>>(3);
        for (int i=0; i<3; i++) {
            rulesByType.add(new ArrayList<Rule>());
        }

        FileInputStream fis;
        try {
            fis = new FileInputStream(rulesFile);
        } catch (FileNotFoundException ex) {
            // Nope, no rules. Nothing else to do!
            return;
        }

        try {
            XmlPullParser parser = Xml.newPullParser();

            parser.setInput(fis, null);

            XmlUtils.beginDocument(parser, TAG_RULES);

            int outerDepth = parser.getDepth();
            while (XmlUtils.nextElementWithin(parser, outerDepth)) {
                int ruleType = -1;

                String tagName = parser.getName();
                if (tagName.equals(TAG_ACTIVITY)) {
                    ruleType = TYPE_ACTIVITY;
                } else if (tagName.equals(TAG_BROADCAST)) {
                    ruleType = TYPE_BROADCAST;
                } else if (tagName.equals(TAG_SERVICE)) {
                    ruleType = TYPE_SERVICE;
                }

                if (ruleType != -1) {
                    Rule rule = new Rule();

                    List<Rule> rules = rulesByType.get(ruleType);

                    // if we get an error while parsing a particular rule, we'll just ignore
                    // that rule and continue on with the next rule
                    try {
                        rule.readFromXml(parser);
                    } catch (XmlPullParserException ex) {
                        Slog.e(TAG, "Error reading an intent firewall rule from " + rulesFile, ex);
                        continue;
                    }

                    rules.add(rule);
                }
            }
        } catch (XmlPullParserException ex) {
            // if there was an error outside of a specific rule, then there are probably
            // structural problems with the xml file, and we should completely ignore it
            Slog.e(TAG, "Error reading intent firewall rules from " + rulesFile, ex);
            return;
        } catch (IOException ex) {
            Slog.e(TAG, "Error reading intent firewall rules from " + rulesFile, ex);
            return;
        } finally {
            try {
                fis.close();
            } catch (IOException ex) {
                Slog.e(TAG, "Error while closing " + rulesFile, ex);
            }
        }

        for (int ruleType=0; ruleType<rulesByType.size(); ruleType++) {
            List<Rule> rules = rulesByType.get(ruleType);
            FirewallIntentResolver resolver = resolvers[ruleType];

            for (int ruleIndex=0; ruleIndex<rules.size(); ruleIndex++) {
                Rule rule = rules.get(ruleIndex);
                for (int i=0; i<rule.getIntentFilterCount(); i++) {
                    resolver.addFilter(rule.getIntentFilter(i));
                }
                for (int i=0; i<rule.getComponentFilterCount(); i++) {
                    resolver.addComponentFilter(rule.getComponentFilter(i), rule);
                }
                for (int i=0; i<rule.getPackagePairFilterCount(); i++) {
                    resolver.addPackagePairFilter(rule.getPackagePair(i), rule);
                }
                for (int i=0; i<rule.getUserFilterCount(); i++) {
                    resolver.addUserIdFilter(rule.getUserId(i), rule);
                }
                for (int i=0; i<rule.getDataFilterCount(); i++) {
                    resolver.addDataFilter(rule.getData(i), rule);
                }
                for (int i=0; i<rule.getExtraFilterCount(); i++) {
                    resolver.addExtraFilter(rule.getExtra(i), rule);
                }
            }
        }
    }

    static Filter parseFilter(XmlPullParser parser) throws IOException, XmlPullParserException {
        String elementName = parser.getName();

        FilterFactory factory = factoryMap.get(elementName);

        if (factory == null) {
            throw new XmlPullParserException("Unknown element in filter list: " + elementName);
        }
        return factory.newFilter(parser);
    }

    /**
     * Represents a single activity/service/broadcast rule within one of the xml files.
     *
     * Rules are matched against an incoming intent in two phases. The goal of the first phase
     * is to select a subset of rules that might match a given intent.
     *
     * For the first phase, we use a combination of intent filters (via an IntentResolver)
     * and component filters to select which rules to check. If a rule has multiple intent or
     * component filters, only a single filter must match for the rule to be passed on to the
     * second phase.
     *
     * In the second phase, we check the specific conditions in each rule against the values in the
     * intent. All top level conditions (but not filters) in the rule must match for the rule as a
     * whole to match.
     *
     * If the rule matches, then we block or log the intent, as specified by the rule. If multiple
     * rules match, we combine the block/log flags from any matching rule.
     */
    private static class Rule extends AndFilter {
        private static final String TAG_INTENT_FILTER = "intent-filter";
        private static final String TAG_COMPONENT_FILTER = "component-filter";
        private static final String ATTR_NAME = "name";
        private static final String TAG_PACKAGE_FILTER = "package-filter";
        private static final String ATTR_SENDER = "sender";
        private static final String ATTR_RECEIVER = "receiver";
        private static final String TAG_USER = "user-id";
        private static final String ATTR_USER_ID = "sender";
        private static final String TAG_DATA = "data";
        private static final String ATTR_CONTAINS = "contains";
        private static final String TAG_EXTRA = "extra";
        private static final String ATTR_TYPE = "type";
        private static final String ATTR_VALUE = "value";

        private static final String ATTR_BLOCK = "block";
        private static final String ATTR_LOG = "log";

        private final ArrayList<FirewallIntentFilter> mIntentFilters =
                new ArrayList<FirewallIntentFilter>(1);
        private final ArrayList<ComponentName> mComponentFilters = new ArrayList<ComponentName>(0);
        private final ArrayList<PackagePair> mPackagePairFilters = new ArrayList<PackagePair>(0);
        private final ArrayList<String> mUserFilters = new ArrayList<String>(0);
        private final ArrayList<String> mDataFilters = new ArrayList<String>(0);
        private final ArrayList<String[]> mExtraFilters = new ArrayList<String[]>(0);
        private boolean block;
        private boolean log;

        @Override
        public Rule readFromXml(XmlPullParser parser) throws IOException, XmlPullParserException {
            block = Boolean.parseBoolean(parser.getAttributeValue(null, ATTR_BLOCK));
            log = Boolean.parseBoolean(parser.getAttributeValue(null, ATTR_LOG));

            super.readFromXml(parser);
            return this;
        }

        @Override
        protected void readChild(XmlPullParser parser) throws IOException, XmlPullParserException {
            String currentTag = parser.getName();

            // Intent filter
            if (currentTag.equals(TAG_INTENT_FILTER)) {
                FirewallIntentFilter intentFilter = new FirewallIntentFilter(this);
                intentFilter.readFromXml(parser);
                mIntentFilters.add(intentFilter);
            // User filter
            } else if (currentTag.equals(TAG_USER)) {
                String userId = parser.getAttributeValue(null, ATTR_USER_ID);
                if (userId == null) {
                    throw new XmlPullParserException("Id of user cannot be null.", parser, null);
                }
                mUserFilters.add(userId);
            // Data filter
            } else if (currentTag.equals(TAG_DATA)) {
                String dataContains = parser.getAttributeValue(null, ATTR_CONTAINS);
                if (dataContains == null) {
                    throw new XmlPullParserException("Data contains attribute cannot be null.");
                }
                mDataFilters.add(dataContains);
            // Extra filter
            } else if (currentTag.equals(TAG_EXTRA)) {
                String extraType = parser.getAttributeValue(null, ATTR_TYPE);
                String extraValue = parser.getAttributeValue(null, ATTR_VALUE);
                if (extraType == null || extraValue == null) {
                    throw new XmlPullParserException("Extra rules must contain type and value.");
                }
                String[] extraRule = {extraType, extraValue};
                mExtraFilters.add(extraRule);
            // Package filter
            } else if (currentTag.equals(TAG_PACKAGE_FILTER)) {
                String senderPackage = parser.getAttributeValue(null, ATTR_SENDER);
                String receiverPackage = parser.getAttributeValue(null, ATTR_RECEIVER);
                if (senderPackage == null || receiverPackage == null) {
                    throw new XmlPullParserException("Package sender and receiver must be specified.",
                            parser, null);
                }
                mPackagePairFilters.add(new PackagePair(senderPackage, receiverPackage));
            // Component filter
            } else if (currentTag.equals(TAG_COMPONENT_FILTER)) {
                String componentStr = parser.getAttributeValue(null, ATTR_NAME);
                if (componentStr == null) {
                    throw new XmlPullParserException("Component name must be specified.",
                            parser, null);
                }

                ComponentName componentName = ComponentName.unflattenFromString(componentStr);
                if (componentName == null) {
                    throw new XmlPullParserException("Invalid component name: " + componentStr);
                }

                mComponentFilters.add(componentName);
            } else {
                super.readChild(parser);
            }
        }

        public int getIntentFilterCount() {
            return mIntentFilters.size();
        }

        public FirewallIntentFilter getIntentFilter(int index) {
            return mIntentFilters.get(index);
        }

        public int getComponentFilterCount() {
            return mComponentFilters.size();
        }

        public int getPackagePairFilterCount() {
            return mPackagePairFilters.size();
        }

        public int getUserFilterCount() {
            return mUserFilters.size();
        }

        public int getDataFilterCount() {
            return mDataFilters.size();
        }

        public int getExtraFilterCount() {
            return mExtraFilters.size();
        }

        public ComponentName getComponentFilter(int index) {
            return mComponentFilters.get(index);
        }

        public PackagePair getPackagePair(int index) {
            return mPackagePairFilters.get(index);
        }

        public String getUserId(int index) {
            return mUserFilters.get(index);
        }

        public String getData(int index) {
            return mDataFilters.get(index);
        }

        public String[] getExtra(int index) {
            return mExtraFilters.get(index);
        }

        public boolean getBlock() {
            return block;
        }

        public boolean getLog() {
            return log;
        }
    }

    private static class FirewallIntentFilter extends IntentFilter {
        private final Rule rule;

        public FirewallIntentFilter(Rule rule) {
            this.rule = rule;
        }
    }

    private static class FirewallIntentResolver
            extends IntentResolver<FirewallIntentFilter, Rule> {
        @Override
        protected boolean allowFilterResult(FirewallIntentFilter filter, List<Rule> dest) {
            return !dest.contains(filter.rule);
        }

        @Override
        protected boolean isPackageForFilter(String packageName, FirewallIntentFilter filter) {
            return true;
        }

        @Override
        protected FirewallIntentFilter[] newArray(int size) {
            return new FirewallIntentFilter[size];
        }

        @Override
        protected Rule newResult(FirewallIntentFilter filter, int match, int userId) {
            return filter.rule;
        }

        @Override
        protected void sortResults(List<Rule> results) {
            // there's no need to sort the results
            return;
        }

        public void queryByComponent(ComponentName componentName, List<Rule> candidateRules) {
            Rule[] rules = mRulesByComponent.get(componentName);
            if (rules != null) {
                candidateRules.addAll(Arrays.asList(rules));
            }
        }

        public void addComponentFilter(ComponentName componentName, Rule rule) {
            Rule[] rules = mRulesByComponent.get(componentName);
            rules = ArrayUtils.appendElement(Rule.class, rules, rule);
            mRulesByComponent.put(componentName, rules);
        }

        public int queryByPackagePair(PackagePair packagePair, List<Rule> candidateRules) {
            Rule[] rules = mRulesByPackagePair.get(packagePair);
            if (rules != null) {
                candidateRules.addAll(Arrays.asList(rules));
                return rules.length;
            }
            return 0;
        }

        public void addPackagePairFilter(PackagePair packagePair, Rule rule) {
            Rule[] rules = mRulesByPackagePair.get(packagePair);
            rules = ArrayUtils.appendElement(Rule.class, rules, rule);
            mRulesByPackagePair.put(packagePair, rules);
        }

        public int queryByUserId(String userId, List<Rule> candidateRules) {
            Rule[] rules = mRulesByUserId.get(userId);
            if (rules != null) {
                candidateRules.addAll(Arrays.asList(rules));
                return rules.length;
            }
            return 0;
        }

        public void addUserIdFilter(String userId, Rule rule) {
            Rule[] rules = mRulesByUserId.get(userId);
            rules = ArrayUtils.appendElement(Rule.class, rules, rule);
            mRulesByUserId.put(userId, rules);
        }

        public int queryByData(String data, List<Rule> candidateRules) {
            ArrayList<Rule> rulesList = new ArrayList<Rule>(0);
            for (int i = 0; i < mRulesByData.size(); i++) {
                Rule[] rules = mRulesByData.valueAt(i);
                if (rules != null) {
                    for (int k=0; k<rules.length; k++) {
                        Rule rule = rules[k];
                        for (int j=0; j<rule.getDataFilterCount(); j++) {
                            String ruleData = rule.getData(i);
                            if (data != null && ruleData != null)
                                if (data.contains(ruleData))
                                    rulesList.add(rule);
                        }
                    }
                }
            }

            if (rulesList.size() > 0) {
                candidateRules.addAll(rulesList);
                return rulesList.size();
            }

            return 0;
        }

        public int queryByExtra(Intent intent, List<Rule> candidateRules) {

            ArrayList<Rule> rulesList = new ArrayList<Rule>(0);
            for (int i = 0; i < mRulesByExtra.size(); i++) {
                Rule[] rules = mRulesByExtra.valueAt(i);
                if (rules != null) {
                    for (int k=0; k<rules.length; k++) {
                        Rule rule = rules[k];
                        for (int j=0; j<rule.getExtraFilterCount(); j++) {
                            String[] extraRule = rule.getExtra(i);
                            String extraType = extraRule[0];
                            String extraValue = extraRule[1];
                            if (compareExtra(intent.getExtras(), extraType, extraValue))
                                rulesList.add(rule);
                        }
                    }
                }
            }

            if (rulesList.size() > 0) {
                candidateRules.addAll(rulesList);
                return rulesList.size();
            }

            return 0;
        }

        /**
         * Helper method for queryByExtra. Takes a bundle, and the type and value for
         * an extra rule and tries to match them. Returns true if a match was found,
         * otherwise returns false.
         */
        private boolean compareExtra(Bundle extras, String type, String value) {

            // extras could be null, in which case there is nothing to check
            if (extras == null) return false;

            Set<String> keys = extras.keySet();

            for(String key : keys) {
                if (type.equalsIgnoreCase("string")) {
                    String keyValue = extras.getString(key, null);
                    if (keyValue != null)
                        if (keyValue.contains(value))
                            return true;
                } else if (type.equalsIgnoreCase("int")) {
                    int keyValue = extras.getInt(key);
                    if (keyValue != 0) {
                        try {
                            if (keyValue == Integer.parseInt(value))
                                return true;
                        } catch (Exception e) {
                            Slog.e(TAG, "Extra rule is type int, but value is not an int");
                        }
                    }
                } else if (type.equalsIgnoreCase("float")) {
                    float keyValue = extras.getFloat(key);
                    if (keyValue != 0.0) {
                        try {
                            if (keyValue == Float.parseFloat(value))
                                return true;
                        } catch (Exception e) {
                            Slog.e(TAG, "Extra rule is type float, but value is not a float");
                        }
                    }
                }
            }
            return false;
        }

        public void addDataFilter(String data, Rule rule) {
            Rule[] rules = mRulesByData.get(data);
            rules = ArrayUtils.appendElement(Rule.class, rules, rule);
            mRulesByData.put(data, rules);
        }

        public void addExtraFilter(String[] extra, Rule rule) {
            Rule[] rules = mRulesByExtra.get(extra);
            rules = ArrayUtils.appendElement(Rule.class, rules, rule);
            mRulesByExtra.put(extra, rules);
        }

        private final ArrayMap<ComponentName, Rule[]> mRulesByComponent =
                  new ArrayMap<ComponentName, Rule[]>(0);

        private final ArrayMap<PackagePair, Rule[]> mRulesByPackagePair =
                  new ArrayMap<PackagePair, Rule[]>(0);

        private final ArrayMap<String, Rule[]> mRulesByData =
                  new ArrayMap<String, Rule[]>(0);

        private final ArrayMap<String[], Rule[]> mRulesByExtra =
                  new ArrayMap<String[], Rule[]>(0);

        private final ArrayMap<String, Rule[]> mRulesByUserId =
                  new ArrayMap<String, Rule[]>(0);

        public int getRulesCount() {
            return mRulesByComponent.size() + mRulesByPackagePair.size() + filterSet().size() +
                   mRulesByUserId.size() + mRulesByData.size() + mRulesByExtra.size();
        }
    }

    final FirewallHandler mHandler;

    private final class FirewallHandler extends Handler {
        public FirewallHandler(Looper looper) {
            super(looper, null, true);
        }

        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case 0:
                    readRulesDir(getRulesDir());
                    break;
                case 1:
                    loadUserFirewall(getRulesDir());
                    break;
                case 2:
                    bindToUFW();
                    break;
            }
        }
    };

    /**
     * Monitors for the creation/deletion/modification of any .xml files in the rule directory
     */
    private class RuleObserver extends FileObserver {
        private static final int MONITORED_EVENTS = FileObserver.CREATE|FileObserver.MOVED_TO|
                FileObserver.CLOSE_WRITE|FileObserver.DELETE|FileObserver.MOVED_FROM;

        public RuleObserver(File monitoredDir) {
            super(monitoredDir.getAbsolutePath(), MONITORED_EVENTS);
        }

        @Override
        public void onEvent(int event, String path) {
            if (path.endsWith(".xml")) {
                // we wait 250ms before taking any action on an event, in order to dedup multiple
                // events. E.g. a delete event followed by a create event followed by a subsequent
                // write+close event
                mHandler.removeMessages(0);
                mHandler.sendEmptyMessageDelayed(0, 250);
            }
            if (path.endsWith("uf.config")) {
                mHandler.removeMessages(1);
                mHandler.sendEmptyMessageDelayed(1, 250);
            }
        }
    }

    /**
     * This interface contains the methods we need from ActivityManagerService. This allows AMS to
     * export these methods to us without making them public, and also makes it easier to test this
     * component.
     *
     * This interface must match the IntentFirewallInterface class defined in ActivityManagerService.java.
     */
    public interface AMSInterface {
        int checkComponentPermission(String permission, int pid, int uid,
                int owningUid, boolean exported);
        int startActivityAsUser(IApplicationThread caller, String callingPackage,
                Intent intent, String resolvedType, IBinder resultTo, String resultWho, int requestCode,
                int startFlags, ProfilerInfo profilerInfo, Bundle options, int userId);
        int bindService(IApplicationThread caller, IBinder token,
                Intent service, String resolvedType,
                IServiceConnection connection, int flags, int userId);
        IBinder peekService(Intent service, String resolvedType);
        ComponentName startService(IApplicationThread caller, Intent service,
                String resolvedType, int userId);
        int stopService(IApplicationThread caller, Intent service,
                String resolvedType, int userId);
        int broadcastIntent(IApplicationThread caller, Intent intent, String resolvedType, IIntentReceiver resultTo,
                int resultCode, String resultData, Bundle map, String requiredPermission, int appOp,
                boolean serialized, boolean sticky, int userId);
        Context getSystemContext();
        Object getAMSLock();
    }

    /**
     * Checks if the caller has access to a component
     *
     * @param permission If present, the caller must have this permission
     * @param pid The pid of the caller
     * @param uid The uid of the caller
     * @param owningUid The uid of the application that owns the component
     * @param exported Whether the component is exported
     * @return True if the caller can access the described component
     */
    boolean checkComponentPermission(String permission, int pid, int uid, int owningUid,
            boolean exported) {
        return mAms.checkComponentPermission(permission, pid, uid, owningUid, exported) ==
                PackageManager.PERMISSION_GRANTED;
    }

    boolean signaturesMatch(int uid1, int uid2) {
        try {
            IPackageManager pm = AppGlobals.getPackageManager();
            return pm.checkUidSignatures(uid1, uid2) == PackageManager.SIGNATURE_MATCH;
        } catch (RemoteException ex) {
            Slog.e(TAG, "Remote exception while checking signatures", ex);
            return false;
        }
    }

    /**
     * Interface so IFW can bind to UFW.
     */
    private class UFWServiceConnection implements ServiceConnection {

        @Override
        public void onServiceConnected(ComponentName comp, IBinder service) {
            forwardUserFirewall = true;
            Slog.i(TAG, "Connection to UFW established.");
            // Store messenger
            mUFWService = new Messenger(service);
        }

        @Override
        public void onServiceDisconnected(ComponentName comp) {
            forwardUserFirewall = false;
            mUFWService = null;
            Slog.w(TAG, "Connection with UFW lost!");
            mHandler.sendEmptyMessageDelayed(1, 250);
        }
    }

    /**
     * Handler for messages received from the UFW.
     */
    private class UFWHandler extends Handler {

        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case CHECK_INTENT:
                    Bundle data = msg.getData();
                    if (data == null) break;
                    if (!validateData(data)) break;
                    int intentType = data.getInt("intentType", -1);
                    if (intentType == TYPE_ACTIVITY)
                        sendActivityAsUser(data);
                    if (intentType == TYPE_SERVICE)
                        sendServiceAsUser(data);
                    if (intentType == TYPE_BROADCAST)
                        sendBroadcastAsUser(data);
                break;
            }
        }
    }

    /**
     * Validates bundles received from the user firewall.
     *
     * Returns true if the bundle is valid, otherwise returns false.
     */
    private boolean validateData(Bundle data) {
        // Every bundle should have an intent
        Intent intent = data.getParcelable("intent");
        if (intent == null) return false;
        // Every intent should have a valid token
        if (validateToken(intent) != TOKEN_VALID) return false;
        // All checks passed
        return true;
    }

    private void sendActivityAsUser(Bundle data) {
        IApplicationThread caller = ApplicationThreadNative.asInterface(data.getBinder("caller"));
        String callingPackage = data.getString("callingPackage");
        Intent intent = data.getParcelable("intent");
        String resolvedType = data.getString("resolvedType");
        IBinder resultTo = data.getBinder("resultTo");
        String resultWho = data.getString("resultWho");
        int requestCode = data.getInt("requestCode");
        int startFlags = data.getInt("startFlags");
        Bundle options = data.getBundle("options");
        int userId = data.getInt("userId");

        int res =  mAms.startActivityAsUser(caller, callingPackage, intent, resolvedType, resultTo,
            resultWho, requestCode, startFlags, null, options, userId);

        if (res < 0) Slog.w(TAG, "AMS startActivityAsUser returned error: " + res);
    }

    private void sendServiceAsUser(Bundle data) {
        // Determine how this service needs to be sent
        Intent intent = data.getParcelable("intent");
        String serviceAction = data.getString(IFW_SERVICE_ACTION);
        if (serviceAction == null) {
            Slog.w(TAG, "Received service intent from user firewall with no API mark!");
            return;
        }

        if (serviceAction.equals("start")) {
            IApplicationThread caller = ApplicationThreadNative.asInterface(data.getBinder("caller"));
            String resolvedType = data.getString("resolvedType");
            int userId = data.getInt("userId");
            mAms.startService(caller, intent, resolvedType, userId);
        }
        if (serviceAction.equals("bind")) {
            IApplicationThread caller = ApplicationThreadNative.asInterface(data.getBinder("caller"));
            IBinder token = data.getBinder("token");
            String resolvedType = data.getString("resolvedType");
            IServiceConnection connection = IServiceConnection.Stub.asInterface(data.getBinder("connection"));
            int flags = data.getInt("flags");
            int userId = data.getInt("userId");
            mAms.bindService(caller, token, intent, resolvedType, connection, flags, userId);
        }
        if (serviceAction.equals("stop")) {
            IApplicationThread caller = ApplicationThreadNative.asInterface(data.getBinder("caller"));
            String resolvedType = data.getString("resolvedType");
            int userId = data.getInt("userId");
            mAms.stopService(caller, intent, resolvedType, userId);
        }
        if (serviceAction.equals("peek")) {
            String resolvedType = data.getString("resolvedType");
            mAms.peekService(intent, resolvedType);
        }
    }

    private void sendBroadcastAsUser(Bundle data) {
        IApplicationThread caller = ApplicationThreadNative.asInterface(data.getBinder("caller"));
        Intent intent = data.getParcelable("intent");
        String resolvedType = data.getString("resolvedType");
        IIntentReceiver resultTo = IIntentReceiver.Stub.asInterface(data.getBinder("resultTo"));
        int resultCode = data.getInt("resultCode");
        String resultData = data.getString("resultData");
        Bundle map = data.getBundle("map");
        String requiredPermission = data.getString("requiredPermission");
        int appOp = data.getInt("appOp");
        boolean serialized = data.getBoolean("serialized");
        boolean sticky = data.getBoolean("sticky");
        int userId = data.getInt("userId");

        int res = mAms.broadcastIntent(caller, intent, resolvedType, resultTo, resultCode, resultData, map,
            requiredPermission, appOp, serialized, sticky, userId);

        if (res < 0) Slog.w(TAG, "AMS broadcastIntent returned error: " + res);
    }

    /**
     * Holds a pair of package names as two strings referring to the sending and receiving
     * packages.
     *
     * This class allows the intent firewall to match intents based on both the sending
     * and receiving package names. Such a rule can be defined in the following way:
     *
     *     <package-filter sender="[package]" receiver="[package]" />
     *
     * and will be checked whenever the sender's package name is given to the intent firewall.
     *
     * To have a sender match any receiver, set the receiver to "*".
     */
    private static final class PackagePair {

        private String senderPackage, receiverPackage;

        /**
         * @param senderPkg The sender's package name. Cannot be null.
         * @param receiverPkg The receiver's package name. Cannot be null.
         */
        public PackagePair(String senderPkg, String receiverPkg) {
            if (senderPkg == null) throw new NullPointerException("sender package name is null");
            if (receiverPkg == null) throw new NullPointerException("receiver package name is null");
            senderPackage = senderPkg;
            receiverPackage = receiverPkg;
        }

        // This class requires a special notion of equality so it is matchable when stored as a key
        // in an array map.
        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final PackagePair pkg = (PackagePair) obj;
            if (!this.getSenderPackageName().equals(pkg.getSenderPackageName())) {
                return false;
            }
            if (!this.getReceiverPackageName().equals(pkg.getReceiverPackageName())
                && !this.getReceiverPackageName().equals("*")) {
                return false;
            }
            return true;
        }

        // This class also requires a special notion of hash code so it is matchable when stored
        // as a key in an array map.
        @Override
        public int hashCode() {
            int hash = 3;
            hash = 53 * hash + this.getSenderPackageName().hashCode();
            hash = 53 * hash + this.getReceiverPackageName().hashCode();
            return hash;
        }

        public String getSenderPackageName() {
            return senderPackage;
        }

        public String getReceiverPackageName() {
            return receiverPackage;
        }
    }
}
