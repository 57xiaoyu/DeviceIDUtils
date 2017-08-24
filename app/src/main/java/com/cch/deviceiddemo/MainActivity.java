package com.cch.deviceiddemo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView tv_id = (TextView) findViewById(R.id.tv_id);
        tv_id.setText(String.format("Deviceid:%s",DeviceIDUtils.getDeviceId(this)));
    }
}
