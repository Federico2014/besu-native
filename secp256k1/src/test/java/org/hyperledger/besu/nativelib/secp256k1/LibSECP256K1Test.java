/*
 * Copyright Hyperledger Besu contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See
 *  the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.besu.nativelib.secp256k1;

import com.sun.jna.ptr.LongByReference;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.hyperledger.besu.nativelib.common.utils.ByteArray;
import org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1.secp256k1_ecdsa_recoverable_signature;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1.SECP256K1_EC_UNCOMPRESSED;

public class LibSECP256K1Test {

  private static byte[] data;
  private static byte[] privateKey;
  private static byte[] dataHash;

  @BeforeClass
  public static void setUp() throws NoSuchAlgorithmException {
    SecureRandom random =  new SecureRandom();
    data = new byte[128];
    privateKey = new byte[32];
    random.nextBytes(data);
    random.nextBytes(privateKey);
    privateKey[0] &= 0x7F;

    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    dataHash = digest.digest(data);
  }

  @Test
  public void signTest() {
    final LibSecp256k1.secp256k1_pubkey pubKey = new LibSecp256k1.secp256k1_pubkey();
    if (LibSecp256k1.secp256k1_ec_pubkey_create(
        LibSecp256k1.CONTEXT, pubKey, privateKey)
        == 0) {
      throw new RuntimeException("Could not create public key from private key.");
    }

    final ByteBuffer recoveredKey = ByteBuffer.allocate(65);
    final LongByReference keySize = new LongByReference(recoveredKey.limit());
    if (LibSecp256k1.secp256k1_ec_pubkey_serialize(
        LibSecp256k1.CONTEXT,
        recoveredKey,
        keySize,
        pubKey,
        SECP256K1_EC_UNCOMPRESSED
    ) == 0) {
      throw new RuntimeException("Could not serialize public key.");
    }

    final LibSecp256k1.secp256k1_ecdsa_recoverable_signature signature =
        new secp256k1_ecdsa_recoverable_signature();

    if (LibSecp256k1.secp256k1_ecdsa_sign_recoverable(
        LibSecp256k1.CONTEXT,
        signature,
        dataHash,
        privateKey,
        null,
        null)
        == 0) {
      throw new RuntimeException(
          "Could not natively sign. Private Key is invalid or default nonce generation failed.");
    }

    final LibSecp256k1.secp256k1_pubkey newPubKey = new LibSecp256k1.secp256k1_pubkey();
    if (LibSecp256k1.secp256k1_ecdsa_recover(
        LibSecp256k1.CONTEXT, newPubKey, signature, dataHash)
        == 0) {
      throw new IllegalArgumentException("Could not parse pub key");
    }

    final ByteBuffer recoveredKey2 = ByteBuffer.allocate(65);
    final LongByReference keySize2 = new LongByReference(recoveredKey2.limit());

    LibSecp256k1.secp256k1_ec_pubkey_serialize(
        LibSecp256k1.CONTEXT, recoveredKey2, keySize2, newPubKey, SECP256K1_EC_UNCOMPRESSED);

    Assert.assertArrayEquals(recoveredKey.array(), recoveredKey2.array());
  }

  private byte[] sign() {
    final LibSecp256k1.secp256k1_ecdsa_recoverable_signature signature =
        new secp256k1_ecdsa_recoverable_signature();

    if (LibSecp256k1.secp256k1_ecdsa_sign_recoverable(
        LibSecp256k1.CONTEXT,
        signature,
        dataHash,
        privateKey,
        null,
        null)
        == 0) {
      throw new RuntimeException(
          "Could not natively sign. Private Key is invalid or default nonce generation failed.");
    }

    final LibSecp256k1.secp256k1_pubkey newPubKey = new LibSecp256k1.secp256k1_pubkey();
    if (LibSecp256k1.secp256k1_ecdsa_recover(
        LibSecp256k1.CONTEXT, newPubKey, signature, dataHash)
        == 0) {
      throw new IllegalArgumentException("Could not parse pub key");
    }

    final ByteBuffer recoveredKey = ByteBuffer.allocate(65);
    final LongByReference keySize = new LongByReference(recoveredKey.limit());

    LibSecp256k1.secp256k1_ec_pubkey_serialize(
        LibSecp256k1.CONTEXT, recoveredKey, keySize, newPubKey, SECP256K1_EC_UNCOMPRESSED);
    return recoveredKey.array();
  }


  @Test
  public void ConcurrentSignTest() throws InterruptedException {
    int threads = 32;
    int singThreadIterations = 100;

    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch latch = new CountDownLatch(threads * singThreadIterations);
    final Throwable[] lastException = new Throwable[1];

    final LibSecp256k1.secp256k1_pubkey pubKey = new LibSecp256k1.secp256k1_pubkey();
    if (LibSecp256k1.secp256k1_ec_pubkey_create(
        LibSecp256k1.CONTEXT, pubKey, privateKey)
        == 0) {
      throw new RuntimeException("Could not create public key from private key.");
    }

    final ByteBuffer recoveredKey = ByteBuffer.allocate(65);
    final LongByReference keySize = new LongByReference(recoveredKey.limit());
    if (LibSecp256k1.secp256k1_ec_pubkey_serialize(
        LibSecp256k1.CONTEXT,
        recoveredKey,
        keySize,
        pubKey,
        SECP256K1_EC_UNCOMPRESSED
    ) == 0) {
      throw new RuntimeException("Could not serialize public key.");
    }

    for (int i = 0; i < threads * singThreadIterations; i++) {
      pool.submit(() -> {
        try {
          byte[] result = sign();
          Assert.assertArrayEquals(recoveredKey.array(), result);
        } catch (Throwable t) {
          lastException[0] = t;
        } finally {
          latch.countDown();
        }
      });

    }
    latch.await();
    pool.shutdown();

    if (lastException[0] != null) {
      throw new AssertionError(lastException[0]);
    }
  }

  @Test
  public void testPubkey() {
    byte[] privateKey;
    int ret;
    final LibSecp256k1.secp256k1_pubkey pubKey = new LibSecp256k1.secp256k1_pubkey();
    privateKey = new byte[0];
    ret = LibSecp256k1.secp256k1_ec_pubkey_create(LibSecp256k1.CONTEXT, pubKey, privateKey);
    Assert.assertEquals(0, ret);

    privateKey = new byte[32];
    privateKey[31] = 1;
    ret = LibSecp256k1.secp256k1_ec_pubkey_create(LibSecp256k1.CONTEXT, pubKey, privateKey);
    Assert.assertEquals(1, ret);

    final ByteBuffer recoveredKey = ByteBuffer.allocate(65);
    final LongByReference keySize = new LongByReference(recoveredKey.limit());
    if (LibSecp256k1.secp256k1_ec_pubkey_serialize(
        LibSecp256k1.CONTEXT,
        recoveredKey,
        keySize,
        pubKey,
        SECP256K1_EC_UNCOMPRESSED
    ) == 0) {
      throw new RuntimeException("Could not serialize public key.");
    }

    // test for N
    privateKey = ByteArray.hexStringToBytes(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    ret = LibSecp256k1.secp256k1_ec_pubkey_create(LibSecp256k1.CONTEXT, pubKey, privateKey);
    Assert.assertEquals(0, ret);

    // test for N-1
    privateKey = ByteArray.hexStringToBytes(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
    ret = LibSecp256k1.secp256k1_ec_pubkey_create(LibSecp256k1.CONTEXT, pubKey, privateKey);
    Assert.assertEquals(1, ret);
  }

}
