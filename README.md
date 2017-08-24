# DeviceIDUtils
A tool class that gets the unique ID of the Android device（一个获取Android设备唯一id的工具类）
最近项目中遇到需要获取设备唯一ID与账户绑定的情况，传统做法是取IMEI值，由于需要与账号绑定，这个值的唯一性很重要，但对于双卡双待手机，使用TelephonyManager获取设备ID在网络制式变化如从GSM变为CDMA时会变化，而且有的手机会存在IMEI为空的情况，为此写了这个工具类获取设备ID

思路大致是这样的：
首先获取IMEI如果为空则取Mac地址，如果还为空则获取设备的硬件信息拼接的信息
为了保证获取的值的唯一性引入缓存机制
在第一次调用getDeviceId时会在SD卡中建立一个隐藏文件存储这个值，之后如果这个文件存在都取这个文件存的值


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView tv_id = (TextView) findViewById(R.id.tv_id);
        tv_id.setText(String.format("Deviceid:%s",DeviceIDUtils.getDeviceId(getApplicationContext())));
    }
    

