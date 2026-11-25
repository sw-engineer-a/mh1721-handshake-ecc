package com.mh1721.handshake.ecc;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.os.Build;
import android.os.Bundle;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Arrays;

public class MainActivity extends Activity {
    private static final String ACTION_USB_PERMISSION = "com.mh1721.handshake.ecc.USB_PERMISSION";

    private UsbManager usbManager;
    private TextView output;
    private byte[] pendingSecret;
    private BroadcastReceiver usbPermissionReceiver;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        usbManager = (UsbManager) getSystemService(USB_SERVICE);
        output = findViewById(R.id.output);
        output.setText("The phone and the MH1721 share a P-256 key. A block is 32 bytes. Hello returns the 65-byte public point and the curve id 0017.");
        findViewById(R.id.phone).setOnClickListener(v -> runPhone());
        findViewById(R.id.board).setOnClickListener(v -> startBoard());
    }

    @Override
    protected void onStart() {
        super.onStart();
        usbPermissionReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (!ACTION_USB_PERMISSION.equals(intent.getAction())) {
                    return;
                }
                UsbDevice device = readDevice(intent);
                boolean granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false);
                if (device != null && granted) {
                    talk(device);
                } else {
                    output.setText("USB permission was denied.");
                }
            }
        };
        IntentFilter filter = new IntentFilter(ACTION_USB_PERMISSION);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(usbPermissionReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(usbPermissionReceiver, filter);
        }
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (usbPermissionReceiver != null) {
            unregisterReceiver(usbPermissionReceiver);
            usbPermissionReceiver = null;
        }
    }

    private void runPhone() {
        try {
            byte[] plain = EccBox.plain();
            byte[] sealed = EccBox.encrypt(plain, EccBox.sampleScalar());
            byte[] opened = EccBox.decrypt(sealed);
            byte[] again = EccBox.seal(plain);
            byte[] openedAgain = EccBox.decrypt(again);
            output.setText("phone\npublic point matches " + Arrays.equals(EccBox.derivedPublic(), EccBox.publicPoint())
                    + "\nephemeral point matches " + Arrays.equals(Arrays.copyOf(sealed, EccBox.POINT), EccBox.samplePoint())
                    + "\ncipher matches " + Arrays.equals(Arrays.copyOfRange(sealed, EccBox.POINT, EccBox.OPEN), EccBox.cipher())
                    + "\nopened matches " + Arrays.equals(opened, plain)
                    + "\nrandom opened matches " + Arrays.equals(openedAgain, plain));
        } catch (Exception error) {
            output.setText(error.getClass().getSimpleName() + ": " + error.getMessage());
        }
    }

    private void startBoard() {
        pendingSecret = EccBox.plain();
        ArrayList<UsbDevice> devices = new ArrayList<>(usbManager.getDeviceList().values());
        if (devices.isEmpty()) {
            output.setText("No USB device. Connect the MH1721 with a USB OTG adapter.");
            return;
        }
        UsbDevice device = devices.get(0);
        if (usbManager.hasPermission(device)) {
            talk(device);
            return;
        }
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 31) {
            flags |= PendingIntent.FLAG_MUTABLE;
        }
        Intent permissionIntent = new Intent(ACTION_USB_PERMISSION);
        permissionIntent.setPackage(getPackageName());
        PendingIntent permission = PendingIntent.getBroadcast(this, 0, permissionIntent, flags);
        output.setText("Asking for USB permission.");
        usbManager.requestPermission(device, permission);
    }

    private void talk(UsbDevice device) {
        byte[] secret = pendingSecret;
        output.setText("Opening " + device.getDeviceName());
        new Thread(() -> {
            String text;
            try (BoardLink link = BoardLink.open(usbManager, device)) {
                Frames.PublicKey pub = Frames.parsePublic(link.transact(Frames.request(Frames.HELLO, null)));
                boolean pointMatches = Arrays.equals(pub.point, EccBox.publicPoint());
                boolean curveMatches = Arrays.equals(pub.curve, EccBox.curve());
                if (!pointMatches || !curveMatches) {
                    text = "board\nhandshake failed"
                            + "\npoint matches " + pointMatches
                            + "\ncurve matches " + curveMatches;
                } else {
                    byte[] sealed = EccBox.seal(secret);
                    byte[] opened = link.transact(Frames.request(Frames.OPEN, sealed));
                    text = "board\nhandshake ok"
                            + "\nopen bytes " + sealed.length
                            + "\nplain matches " + Arrays.equals(opened, secret);
                }
            } catch (Exception error) {
                text = error.getClass().getSimpleName() + ": " + error.getMessage();
            }
            String show = text;
            runOnUiThread(() -> output.setText(show));
        }).start();
    }

    private static UsbDevice readDevice(Intent intent) {
        if (Build.VERSION.SDK_INT >= 33) {
            return intent.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice.class);
        }
        return intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
    }
}
