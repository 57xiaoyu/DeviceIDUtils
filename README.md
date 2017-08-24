# DeviceIDUtils
A tool class that gets the unique ID of the Android device（一个获取Android设备唯一id的工具类）



    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView tv_id = (TextView) findViewById(R.id.tv_id);
        tv_id.setText(String.format("Deviceid:%s",DeviceIDUtils.getDeviceId(getApplicationContext())));
    }
    

