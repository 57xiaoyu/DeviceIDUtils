package com.cch.deviceiddemo;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Environment;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.io.Reader;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Fstar on 2017/8/11.
 */

public class DeviceIDUtils {

    /*
    *
    *  <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
    *  <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    *  <uses-permission android:name="android.permission.READ_PHONE_STATE" />
    *
    * */
    private static final String SHARED_PREFERENCES_NAME = "deviceid_cache";
    //.开头隐藏文件和隐藏文件夹
    private static final String FILE_PATH = "data/.cache/.1270f37f6c8";

    private static final String LOACL_UUID = "my_device_localuuid";
    private static final String LOACL_MAC = "my_device_local_mac";
    private static final String LOACL_IMEI = "my_device_local_imei";
    private static final String LOACL_DEVICE_IMEI = "my_device_local_device_imei";


    private static final String LOACL_DEVICE_ID = "my_device_loacl_device_id";

    private static final String LOACL_FILENAME_KEY = "loacl_filename_key";


    private static Context mContext;


    //获取设备唯一id
    public static String getDeviceId(Context context) {
        mContext = context.getApplicationContext();
      /*  Log.d("DeviceIDUtils", "getLocalDeviceId:" + getLocalDeviceId());
        Log.d("DeviceIDUtils", "getMacid:" + getMacid());
        Log.d("DeviceIDUtils", "getMac60:" + getMac60());
        Log.d("DeviceIDUtils", "getMac60_1:" + getMac60_1());
        Log.d("DeviceIDUtils", "getMac60_2:" + getMac60_2());
        Log.d("DeviceIDUtils", "getimei:" + getimei());
        Log.d("DeviceIDUtils", "getDiviceInfoIMEI:" + getDiviceInfoIMEI());
        Log.d("DeviceIDUtils", "getLocalUUID:" + getLocalUUID());
        Log.d("DeviceIDUtils", "getFileName:" + getFileName());
*/
        String localDeviceId = getLocalDeviceId();
        if (!TextUtils.isEmpty(localDeviceId)) {
            return localDeviceId;
        }
        //先获取获取默认的imei
        String diviceid = getimei();

        //如果为空获取MAC地址
        if (TextUtils.isEmpty(diviceid)) {
            diviceid = getMacid();
        }

        //如果还为空择取设备信息拼接出来的id
        if (TextUtils.isEmpty(diviceid)) {
            diviceid = getDiviceInfoIMEI();
        }

        //如果还为空则生成并保存一个唯一的UUID
        if (TextUtils.isEmpty(diviceid)) {
            diviceid = getLocalUUID();
        }

        Log.d("DeviceIDUtils", "return diviceid:" + diviceid);
        saveDeviceId(diviceid);
        return diviceid;
    }

    private static String getLocalDeviceId() {
        String savaString = getSavaString(LOACL_DEVICE_ID, "");
        if (TextUtils.isEmpty(savaString)) {
            String s = readSDFile();
            if (!TextUtils.isEmpty(s)) {
                savaString(LOACL_DEVICE_ID, s);
                return s;
            }
        } else {
            return savaString;
        }

        return null;
    }

    private static void saveDeviceId(String diviceid) {
        savaString(LOACL_DEVICE_ID, diviceid);
        //加密保存
        saveFile(encrypt(diviceid));
    }

    private static void saveFile(String str) {
        String filePath = null;
        boolean hasSDCard = Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED);
        if (hasSDCard) { // SD卡根目录的hello.text
            filePath = Environment.getExternalStorageDirectory().toString() + File.separator + FILE_PATH + File.separator + getFileName();
        } else {  // 系统下载缓存根目录的hello.text
            filePath = Environment.getDownloadCacheDirectory().toString() + File.separator + FILE_PATH + File.separator + getFileName();
        }
        try {
            File file = new File(filePath);
            //不存在則重新保存
            if (!file.exists()) {
                Log.d("DeviceIDUtils", "saveFile filePath:" + filePath);
                File dir = new File(file.getParent());
                dir.mkdirs();
                file.createNewFile();
                FileOutputStream outStream = new FileOutputStream(file);
                outStream.write(str.getBytes());
                outStream.close();
            } else {
                Log.d("DeviceIDUtils", "saveFile 文件已存在:" + filePath);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String getFileName() {
        //两种模式，随机的文件名和固定文件名，可以根据需求自行更换
        //随机的文件名
       /* String savaFileName = getSavaString(LOACL_FILENAME_KEY, "");
        if (TextUtils.isEmpty(savaFileName)) {
            String uuid = UUID.randomUUID().toString().replace("-", "");
            savaString(LOACL_FILENAME_KEY, uuid);
            Log.d("DeviceIDUtils", "getFileName:" + uuid);
            return uuid;
        } else {
            Log.d("DeviceIDUtils", "getFileName:" + savaFileName);
            return savaFileName;
        }*/


        //固定文件名
        return ".abcdefg60232414f87c77dcc737f2f0c";
    }

    private static String readSDFile() {
        try {
            String filePath = null;
            boolean hasSDCard = Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED);
            if (hasSDCard) { // SD卡根目录的hello.text
                filePath = Environment.getExternalStorageDirectory().toString() + File.separator + FILE_PATH + File.separator + getFileName();
            } else {  // 系统下载缓存根目录的hello.text
                filePath = Environment.getDownloadCacheDirectory().toString() + File.separator + FILE_PATH + File.separator + getFileName();
            }
            File file = new File(filePath);
            FileInputStream fis = new FileInputStream(file);
            int length = fis.available();

            byte[] buffer = new byte[length];
            fis.read(buffer);
            String res = new String(buffer, "utf-8");
            ;
            fis.close();
            Log.d("DeviceIDUtils", "readSDFile filePath:" + filePath);
            Log.d("DeviceIDUtils", "readSDFile res:" + res);
            //解密
            return decrypt(res);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }


    private static String getLocalUUID() {
        String localuuid = getSavaString(LOACL_UUID, "");
        if (TextUtils.isEmpty(localuuid)) {
            localuuid = UUID.randomUUID().toString().replace("-", "");
            savaString(LOACL_UUID, localuuid);
        }
        return localuuid;
    }

    private static String getMacid() {
        String WLANMAC = getSavaString(LOACL_MAC, "");
        if (!TextUtils.isEmpty(WLANMAC)) {
            return WLANMAC;
        }

        if (Build.VERSION.SDK_INT >= 23) {
            WLANMAC = getMac60();
        } else {
            WifiManager wm = (WifiManager) mContext.getSystemService(Context.WIFI_SERVICE);
            WLANMAC = wm.getConnectionInfo().getMacAddress();
            if (TextUtils.isEmpty(WLANMAC) || "02:00:00:00:00:00".equals(WLANMAC)) {
                WLANMAC = getMac60();
            }
        }

        //在Android6.0的版本以后用原来的getMacAddress()方法获取手机的MAC地址都为：02:00:00:00:00:00这个固定的值
        if ("02:00:00:00:00:00".equals(WLANMAC)) {
            WLANMAC = null;
        }

        if (!TextUtils.isEmpty(WLANMAC)) {
            WLANMAC = WLANMAC.replaceAll(":", "");
            savaString(LOACL_MAC, WLANMAC);
        }
        return WLANMAC;
    }


    private static String getMac60() {
        String mac = getMac60_1();
        if (TextUtils.isEmpty(mac) || "02:00:00:00:00:00".equals(mac)) {
            mac = getMac60_2();
        }
        return mac;
    }

    private static String getMac60_1() {
        String str = "";
        String macSerial = "";
        try {
            Process pp = Runtime.getRuntime().exec(
                    "cat /sys/class/net/wlan0/address ");
            InputStreamReader ir = new InputStreamReader(pp.getInputStream());
            LineNumberReader input = new LineNumberReader(ir);

            for (; null != str; ) {
                str = input.readLine();
                if (str != null) {
                    macSerial = str.trim();// 去空格
                    break;
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        if (macSerial == null || "".equals(macSerial)) {
            try {
                return loadFileAsString("/sys/class/net/eth0/address")
                        .toUpperCase().substring(0, 17);
            } catch (Exception e) {
                e.printStackTrace();

            }

        }

        //转换成小写
        if (!TextUtils.isEmpty(macSerial)) {
            macSerial = macSerial.toLowerCase();
        }
        return macSerial;
    }

    private static String getMac60_2() {
        try {
            List<NetworkInterface> all = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface nif : all) {
                if (!nif.getName().equalsIgnoreCase("wlan0")) continue;

                byte[] macBytes = nif.getHardwareAddress();
                if (macBytes == null) {
                    return "";
                }

                StringBuilder res1 = new StringBuilder();
                for (byte b : macBytes) {
                    res1.append(String.format("%02X:", b));
                }

                if (res1.length() > 0) {
                    res1.deleteCharAt(res1.length() - 1);
                }
                String mac = res1.toString();
                //转换成小写
                if (!TextUtils.isEmpty(mac)) {
                    mac = mac.toLowerCase();
                }
                return mac;
            }
        } catch (Exception ex) {
        }
        return null;
    }

    private static String loadFileAsString(String fileName) throws Exception {
        FileReader reader = new FileReader(fileName);
        String text = loadReaderAsString(reader);
        reader.close();
        return text;
    }

    private static String loadReaderAsString(Reader reader) throws Exception {
        StringBuilder builder = new StringBuilder();
        char[] buffer = new char[4096];
        int readLength = reader.read(buffer);
        while (readLength >= 0) {
            builder.append(buffer, 0, readLength);
            readLength = reader.read(buffer);
        }
        return builder.toString();
    }


    //通过取出ROM版本、制造商、CPU型号、以及其他硬件信息来实现
    private static String getDiviceInfoIMEI() {
        String device_imei = getSavaString(LOACL_DEVICE_IMEI, "");
        if (!TextUtils.isEmpty(device_imei)) {
            return device_imei;
        }

        device_imei = "35" + //we make this look like a valid IMEI
                Build.BOARD.length() % 10 +
                Build.BRAND.length() % 10 +
                Build.CPU_ABI.length() % 10 +
                Build.DEVICE.length() % 10 +
                Build.DISPLAY.length() % 10 +
                Build.HOST.length() % 10 +
                Build.ID.length() % 10 +
                Build.MANUFACTURER.length() % 10 +
                Build.MODEL.length() % 10 +
                Build.PRODUCT.length() % 10 +
                Build.TAGS.length() % 10 +
                Build.TYPE.length() % 10 +
                Build.USER.length() % 10; //13 digits

        if (!TextUtils.isEmpty(device_imei)) {
            savaString(LOACL_DEVICE_IMEI, device_imei);
        }
        return device_imei;
    }

    private static String getimei() {
        String imei = getSavaString(LOACL_IMEI, "");
        if (!TextUtils.isEmpty(imei)) {
            return imei;
        }

        try {
            TelephonyManager tm = (TelephonyManager) mContext
                    .getSystemService(Context.TELEPHONY_SERVICE);
            imei = tm.getDeviceId();
            if (!TextUtils.isEmpty(imei)) {
                savaString(LOACL_IMEI, imei);
            }
            return imei;
        } catch (Exception e) {

        }
        return null;
    }

    private static String getSavaString(String key, String defValue) {
        SharedPreferences sp = mContext.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        return sp.getString(key, defValue);
    }

    private static void savaString(String key, String value) {
        SharedPreferences sp = mContext.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE);
        sp.edit().putString(key, value).commit();//提交保存键值对

    }


    //****************************************************   以下是加密算法  *********************************************************************//


    private final static String key = "cch@1234sis9876~";//方法一，密匙必须为16位
    private static String ivParameter = "1234567890123456";//默认偏移
    private static String WAYS = "AES";
    private static String MODE = "";
    private static boolean isPwd = false;
    private static String ModeCode = "PKCS5Padding";
    private static int type = 0;// 默认
    private static int pwdLenght = 16;
    private static String val = "0";

    /**
     * @param
     * @return AES加密算法加密
     * @throws Exception
     */
    private static String encrypt(String cleartext) {
        if (cleartext == null) {
            return null;
        }
        try {
            String seed = key;
            byte[] encryptResultStr = new byte[0];
            encryptResultStr = encrypt(cleartext, seed, 0);
            return new String(encryptResultStr);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * @param encrypted
     * @return AES加密算法解密
     * @throws Exception
     */
    private static String decrypt(String encrypted) {
        if (encrypted == null) {
            return null;
        }
        try {
            String seed = key;
            String temp = decrypt(encrypted, seed, 0);
            return temp;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private enum AESType {

        ECB("ECB", "0"), CBC("CBC", "1"), CFB("CFB", "2"), OFB("OFB", "3");
        private String k;
        private String v;

        private AESType(String k, String v) {
            this.k = k;
            this.v = v;
        }

        public String key() {
            return this.k;
        }

        public String value() {
            return this.v;
        }

        public static AESType get(int id) {
            AESType[] vs = AESType.values();
            for (int i = 0; i < vs.length; i++) {
                AESType d = vs[i];
                if (d.key().equals(id))
                    return d;
            }
            return AESType.CBC;
        }

    }

    private static String selectMod(int type) {
        // ECB("ECB", "0"), CBC("CBC", "1"), CFB("CFB", "2"), OFB("OFB", "3");
        switch (type) {
            case 0:
                isPwd = false;
                MODE = WAYS + "/" + AESType.ECB.key() + "/" + ModeCode;

                break;
            case 1:
                isPwd = true;
                MODE = WAYS + "/" + AESType.CBC.key() + "/" + ModeCode;
                break;
            case 2:
                isPwd = true;
                MODE = WAYS + "/" + AESType.CFB.key() + "/" + ModeCode;
                break;
            case 3:
                isPwd = true;
                MODE = WAYS + "/" + AESType.OFB.key() + "/" + ModeCode;
                break;

        }

        return MODE;

    }

    // 加密
    private static byte[] encrypt(String sSrc, String sKey, int type)
            throws Exception {
        sKey = toMakekey(sKey, pwdLenght, val);
        Cipher cipher = Cipher.getInstance(selectMod(type));
        byte[] raw = sKey.getBytes();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, WAYS);

        IvParameterSpec iv = new IvParameterSpec(ivParameter.getBytes());// 使用CBC模式，需要一个向量iv，可增加加密算法的强度
        if (isPwd == false) {// ECB 不用密码
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        }

        byte[] encrypted = cipher.doFinal(sSrc.getBytes("utf-8"));
        return Base64.encode(encrypted, Base64.DEFAULT);// 此处使用BASE64做转码。
    }

    // 解密
    private static String decrypt(String sSrc, String sKey, int type)
            throws Exception {
        sKey = toMakekey(sKey, pwdLenght, val);
        try {
            byte[] raw = sKey.getBytes("ASCII");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, WAYS);
            Cipher cipher = Cipher.getInstance(selectMod(type));
            IvParameterSpec iv = new IvParameterSpec(ivParameter.getBytes());
            if (isPwd == false) {// ECB 不用密码
                cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            }
            byte[] encrypted1 = Base64.decode(sSrc.getBytes(), Base64.DEFAULT);// 先用base64解密
            byte[] original = cipher.doFinal(encrypted1);
            String originalString = new String(original, "utf-8");
            return originalString;
        } catch (Exception ex) {
            return null;
        }
    }

    //key
    private static String toMakekey(String str, int strLength, String val) {

        int strLen = str.length();
        if (strLen < strLength) {
            while (strLen < strLength) {
                StringBuffer buffer = new StringBuffer();
                buffer.append(str).append(val);
                str = buffer.toString();
                strLen = str.length();
            }
        }
        return str;
    }
}
