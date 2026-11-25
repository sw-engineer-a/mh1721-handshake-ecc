package com.mh1721.handshake.ecc;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;

import java.io.Closeable;
import java.io.IOException;
import java.util.Arrays;

/** Bulk USB link. The firmware reads and writes the same frames. */
final class BoardLink implements Closeable {
    private static final int TIMEOUT_MS = 20000;

    private final UsbDeviceConnection connection;
    private final UsbInterface usbInterface;
    private final UsbEndpoint inEndpoint;
    private final UsbEndpoint outEndpoint;
    private byte[] stash = new byte[0];

    private BoardLink(UsbDeviceConnection connection, UsbInterface usbInterface,
                      UsbEndpoint inEndpoint, UsbEndpoint outEndpoint) {
        this.connection = connection;
        this.usbInterface = usbInterface;
        this.inEndpoint = inEndpoint;
        this.outEndpoint = outEndpoint;
    }

    static BoardLink open(UsbManager manager, UsbDevice device) throws IOException {
        UsbInterface chosen = null;
        UsbEndpoint inEndpoint = null;
        UsbEndpoint outEndpoint = null;
        for (int i = 0; i < device.getInterfaceCount() && chosen == null; i++) {
            UsbInterface face = device.getInterface(i);
            UsbEndpoint in = null;
            UsbEndpoint out = null;
            for (int e = 0; e < face.getEndpointCount(); e++) {
                UsbEndpoint endpoint = face.getEndpoint(e);
                if (endpoint.getType() != UsbConstants.USB_ENDPOINT_XFER_BULK) {
                    continue;
                }
                if (endpoint.getDirection() == UsbConstants.USB_DIR_IN) {
                    in = endpoint;
                } else {
                    out = endpoint;
                }
            }
            if (in != null && out != null) {
                chosen = face;
                inEndpoint = in;
                outEndpoint = out;
            }
        }
        if (chosen == null) {
            throw new IOException("the USB device has no bulk in/out pair");
        }
        UsbDeviceConnection connection = manager.openDevice(device);
        if (connection == null || !connection.claimInterface(chosen, true)) {
            if (connection != null) {
                connection.close();
            }
            throw new IOException("could not open the USB device");
        }
        return new BoardLink(connection, chosen, inEndpoint, outEndpoint);
    }

    byte[] transact(byte[] request) throws IOException {
        int sent = 0;
        while (sent < request.length) {
            byte[] chunk = Arrays.copyOfRange(request, sent, request.length);
            int count = connection.bulkTransfer(outEndpoint, chunk, chunk.length, TIMEOUT_MS);
            if (count <= 0) {
                throw new IOException("USB write failed");
            }
            sent += count;
        }
        byte[] header = readExact(3);
        int status = header[0] & 0xff;
        int length = ((header[1] & 0xff) << 8) | (header[2] & 0xff);
        if (length > 512) {
            throw new IOException("board reply is too long");
        }
        byte[] payload = length == 0 ? new byte[0] : readExact(length);
        if (status != 0) {
            throw new IOException("board status " + status);
        }
        return payload;
    }

    @Override
    public void close() {
        connection.releaseInterface(usbInterface);
        connection.close();
    }

    private byte[] readExact(int length) throws IOException {
        byte[] out = new byte[length];
        int filled = 0;
        while (filled < length) {
            if (stash.length > 0) {
                int take = Math.min(stash.length, length - filled);
                System.arraycopy(stash, 0, out, filled, take);
                stash = Arrays.copyOfRange(stash, take, stash.length);
                filled += take;
                continue;
            }
            byte[] packet = new byte[Math.max(inEndpoint.getMaxPacketSize(), 64)];
            int count = connection.bulkTransfer(inEndpoint, packet, packet.length, TIMEOUT_MS);
            if (count <= 0) {
                throw new IOException("USB read failed");
            }
            int take = Math.min(count, length - filled);
            System.arraycopy(packet, 0, out, filled, take);
            filled += take;
            if (count > take) {
                stash = Arrays.copyOfRange(packet, take, count);
            }
        }
        return out;
    }
}
