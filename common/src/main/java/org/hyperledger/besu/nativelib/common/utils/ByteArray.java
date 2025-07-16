package org.hyperledger.besu.nativelib.common.utils;

public class ByteArray {

  private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
  public static final int WORD_SIZE = 32;

  public static String toHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = HEX_ARRAY[v >>> 4];
      hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
    }
    return new String(hexChars);
  }

  public static byte[] fromInts(int... bytes) {
    byte[] result = new byte[bytes.length];
    for (int i = 0; i < bytes.length; i++) {
      result[i] = (byte) bytes[i];
    }
    return result;
  }

  public static byte[] leftPad32(byte[] input) {
    if (input.length > WORD_SIZE) {
      throw new IllegalArgumentException("Input length must be at most " + WORD_SIZE + " bytes.");
    }

    byte[] padded = new byte[WORD_SIZE];
    System.arraycopy(input, 0, padded, WORD_SIZE - input.length, input.length);
    return padded;
  }

  public static byte[] hexStringToBytes(String hex) {
    if (hex == null || hex.isEmpty()) {
//      throw new IllegalArgumentException("Hex string cannot be null or empty.");
      return null;
    }

    if (hex.startsWith("0x")) {
      hex = hex.substring(2);
    }

    int len = hex.length();
    if (len % 2 != 0) {
      throw new IllegalArgumentException("Hex string must have even length.");
    }

    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
          + Character.digit(hex.charAt(i + 1), 16));
    }
    return data;
  }

  public static byte[] concat(byte[]... arrays) {
    if (arrays == null) {
      throw new IllegalArgumentException("Input array cannot be null.");
    }

    int totalLength = 0;
    for (byte[] array : arrays) {
      if (array == null) {
        throw new IllegalArgumentException("Individual byte arrays cannot be null.");
      }
      totalLength += array.length;
    }

    byte[] result = new byte[totalLength];
    int position = 0;
    for (byte[] array : arrays) {
      System.arraycopy(array, 0, result, position, array.length);
      position += array.length;
    }

    return result;
  }

  public static byte[] subArray(byte[] array, int startIndex, int length) {
    if (array == null) {
      throw new IllegalArgumentException("Input array cannot be null.");
    }
    if (startIndex < 0 || length < 0 || startIndex + length > array.length) {
      throw new IndexOutOfBoundsException("Invalid start index or length for array.");
    }

    byte[] result = new byte[length];
    System.arraycopy(array, startIndex, result, 0, length);
    return result;
  }

}
