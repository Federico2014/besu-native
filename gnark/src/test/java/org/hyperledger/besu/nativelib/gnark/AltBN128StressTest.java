package org.hyperledger.besu.nativelib.gnark;

import com.sun.jna.ptr.IntByReference;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.hyperledger.besu.nativelib.common.utils.ByteArray;
import org.junit.Assert;
import org.junit.Test;

public class AltBN128StressTest {

  private int threads = 32;
  private int singThreadIterations = 10;

  private static final String ADD_INPUT =
      "18b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9063c909"
          + "c4720840cb5134cb9f59fa749755796819658d32efc0d288198f3726607c2b7f58a84bd6145f00"
          + "c9c2bc0bb1a187f20ff2c92963a88019e7c6a014eed06614e20c147e940f2d70da3f74c9a17df36"
          + "1706a4485c742bd6788478fa17d7";
  private static final String Add_OUTPUT =
      "2243525c5efd4b9c3d3c45ac0ca3fe4dd85e830a4ce6b65fa1eeaee202839703301d1d33be6"
          + "da8e509df21cc35964723180eed7532537db9ae5e7d48f195c915";

  private static final String MUL_INPUT =
      "2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb721611ce0a6af85915e2f"
          + "1d70300909ce2e49dfad4a4619c8390cae66cefdb20400000000000000000000000000000000000"
          + "000000000000011138ce750fa15c2";
  private static final String MUL_OUTPUT =
      "070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c031b8ce"
          + "914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc";

  private static final String PAIR_INPUT =
      "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811"
          + "c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63"
          + "514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416"
          + "782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf98"
          + "45f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba20"
          + "23c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a"
          + "6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e"
          + "76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395"
          + "bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce"
          + "6cc0166fa7daa";
  private static final String PAIR_OUTPUT =
      "0000000000000000000000000000000000000000000000000000000000000001";

  private volatile Throwable lastException;


  private byte[] add() {
    byte[] input = ByteArray.hexStringToBytes(ADD_INPUT);

    final byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];
    final IntByReference outputLength = new IntByReference();
    final byte[] error = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_ERROR_BYTES];
    final IntByReference errorLength = new IntByReference();

    LibGnarkEIP196.eip196_perform_operation(LibGnarkEIP196.EIP196_ADD_OPERATION_RAW_VALUE, input,
        input.length, output, outputLength, error, errorLength);

    return ByteArray.subArray(output, 0, outputLength.getValue());
  }

  @Test
  public void ConcurrentAddTest() throws InterruptedException {
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch latch = new CountDownLatch(threads * singThreadIterations);

    for (int i = 0; i < threads * singThreadIterations; i++) {
      pool.submit(() -> {
        try {
          byte[] result = add();
          Assert.assertArrayEquals(ByteArray.hexStringToBytes(Add_OUTPUT), result);
        } catch (Throwable t) {
          lastException = t;
        } finally {
          latch.countDown();
        }
      });

    }
    latch.await();
    pool.shutdown();

    if (lastException != null) {
      throw new AssertionError(lastException);
    }
  }

  private byte[] mul() {
    byte[] input = ByteArray.hexStringToBytes(MUL_INPUT);

    final byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];
    final IntByReference outputLength = new IntByReference();
    final byte[] error = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_ERROR_BYTES];
    final IntByReference errorLength = new IntByReference();

    LibGnarkEIP196.eip196_perform_operation(LibGnarkEIP196.EIP196_MUL_OPERATION_RAW_VALUE, input,
        input.length, output, outputLength, error, errorLength);

    return ByteArray.subArray(output, 0, outputLength.getValue());
  }

  @Test
  public void ConcurrentMulTest() throws InterruptedException {
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch latch = new CountDownLatch(threads * singThreadIterations);

    for (int i = 0; i < threads * singThreadIterations; i++) {
      pool.submit(() -> {
        try {
          byte[] result = mul();
          Assert.assertArrayEquals(ByteArray.hexStringToBytes(MUL_OUTPUT), result);
        } catch (Throwable t) {
          lastException = t;
        } finally {
          latch.countDown();
        }
      });
    }
    latch.await();
    pool.shutdown();

    if (lastException != null) {
      throw new AssertionError(lastException);
    }
  }

  private byte[] pair() {
    byte[] input = ByteArray.hexStringToBytes(PAIR_INPUT);

    final byte[] output = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_RESULT_BYTES];
    final IntByReference outputLength = new IntByReference();
    final byte[] error = new byte[LibGnarkEIP196.EIP196_PREALLOCATE_FOR_ERROR_BYTES];
    final IntByReference errorLength = new IntByReference();

    LibGnarkEIP196.eip196_perform_operation(LibGnarkEIP196.EIP196_PAIR_OPERATION_RAW_VALUE, input,
        input.length, output, outputLength, error, errorLength);

    return ByteArray.subArray(output, 0, outputLength.getValue());
  }

  @Test
  public void ConcurrentPairTest() throws InterruptedException {
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch latch = new CountDownLatch(threads * singThreadIterations);

    for (int i = 0; i < threads * singThreadIterations; i++) {
      pool.submit(() -> {
        try {
          byte[] result = pair();
          Assert.assertArrayEquals(ByteArray.hexStringToBytes(PAIR_OUTPUT), result);
        } catch (Throwable t) {
          lastException = t;
        } finally {
          latch.countDown();
        }
      });
    }
    latch.await();
    pool.shutdown();

    if (lastException != null) {
      throw new AssertionError(lastException);
    }
  }
}
