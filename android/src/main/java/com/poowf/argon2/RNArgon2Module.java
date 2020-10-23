package com.poowf.argon2;

import android.app.Activity;
import android.content.Intent;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.bridge.Promise;

import java.util.Base64;

import org.signal.argon2.Argon2;
import org.signal.argon2.Version;
import org.signal.argon2.Type;
import org.signal.argon2.MemoryCost;

public class RNArgon2Module extends ReactContextBaseJavaModule {
    private ReactContext mReactContext;

    public RNArgon2Module(ReactApplicationContext reactContext) {
        super(reactContext);
        mReactContext = reactContext;
    }

    @Override
    public String getName() {
        return "RNArgon2";
    }

    @ReactMethod
    public void argon2(ReadableMap params, Promise promise) {
        String typeString = params.getString("type")
        Type type = Type.Argon2d;
        if("d".equals(typeString) == 0) {
            type = Type.Argon2d;
        } else if ("id".equals(typeString) == 0) {
            type = Type.Argon2id;
        } else if ("i".equals(typeString) == 0) {
            type = Type.Argon2i;
        }
        try {
            Argon2 argon2 = new Argon2.Builder(Version.V13)
                    .iterations(params.getInt("iterations"))
                    // .memoryCost(MemoryCost.MiB(32))
                    .memoryCost(params.getInt("memory"))
                    .parallelism(params.getInt("parallelism"))
                    .hashLength(params.getInt("hashLen"))
                    .type(type)
                    .build();

            final byte[] passwordBytes = Base64.getDecodeder().decode(params.getString("password"));
            final byte[] saltBytes = Base64.getDecodeder().decode(params.getString("salt"));

            Argon2.Result result = argon2.hash(passwordBytes, saltBytes);

            WritableMap resultMap = new WritableNativeMap();
            resultMap.putString("rawHash", result.getHashHex());
            resultMap.putString("encodedHash", result.getEncoded());

            promise.resolve(resultMap);
        } catch (Exception exception) {
            promise.reject("Failed to generate argon2 hash", exception);
        }

    }
}
