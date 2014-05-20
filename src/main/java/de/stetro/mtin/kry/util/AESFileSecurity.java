package de.stetro.mtin.kry.util;

import java.io.InputStream;

public interface AESFileSecurity {
    public void encrypt(char[] password, String mode, InputStream file, String newFileName) throws Exception;

    public void decrypt(char[] password, String mode, InputStream file, String newFileName) throws Exception;
}
