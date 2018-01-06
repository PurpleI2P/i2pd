package org.purplei2p.i2pd;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import android.content.Context;
import android.util.Log;

public class Decompress {
    private static final int BUFFER_SIZE = 1024 * 10;
    private static final String TAG = "Decompress";

    public static void unzipFromAssets(Context context, String zipFile, String destination) {
        try {
            if (destination == null || destination.length() == 0)
                destination = context.getFilesDir().getAbsolutePath();
            InputStream stream = context.getAssets().open(zipFile);
            unzip(stream, destination);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void unzip(String zipFile, String location) {
        try {
            FileInputStream fin = new FileInputStream(zipFile);
            unzip(fin, location);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

    }

    public static void unzip(InputStream stream, String destination) {
        dirChecker(destination, "");
        byte[] buffer = new byte[BUFFER_SIZE];
        try {
            ZipInputStream zin = new ZipInputStream(stream);
            ZipEntry ze = null;

            while ((ze = zin.getNextEntry()) != null) {
                Log.v(TAG, "Unzipping " + ze.getName());

                if (ze.isDirectory()) {
                    dirChecker(destination, ze.getName());
                } else {
                    File f = new File(destination + ze.getName());
                    if (!f.exists()) {
                        FileOutputStream fout = new FileOutputStream(destination + ze.getName());
                        int count;
                        while ((count = zin.read(buffer)) != -1) {
                            fout.write(buffer, 0, count);
                        }
                        zin.closeEntry();
                        fout.close();
                    }
                }

            }
            zin.close();
        } catch (Exception e) {
            Log.e(TAG, "unzip", e);
        }

    }

    private static void dirChecker(String destination, String dir) {
        File f = new File(destination + dir);

        if (!f.isDirectory()) {
            boolean success = f.mkdirs();
            if (!success) {
                Log.w(TAG, "Failed to create folder " + f.getName());
            }
        }
    }
}
