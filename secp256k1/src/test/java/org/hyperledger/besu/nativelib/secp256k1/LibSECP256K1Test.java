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
import org.hyperledger.besu.nativelib.common.utils.ByteArray;
import org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1.secp256k1_ecdsa_recoverable_signature;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1.SECP256K1_EC_UNCOMPRESSED;

public class LibSECP256K1Test {

  final private byte[] data = ByteArray.hexStringToBytes(
      "c35e2f092553c55772926bdbe87c9796827d17024dbb9233a545366e2e5987dd344deb72df987144b8c6c43bc41b654b94cc856e16b96d7a821c8ec039b503e3d86728c494a967d83011a0e090b5d54cd47f4e366c0912bc808fbb2ea96efac88fb3ebec9342738e225f7c7c2b011ce375b56621a20642b4d36e060db4524af1");
  final private byte[] privateKey = ByteArray
      .hexStringToBytes("0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813");
  final private byte[] publicKey = ByteArray.hexStringToBytes(
      "040efc15cf0638b99ca1cef370a74aceccb950d5e0531bc1526ac0fa9ca90c11766ec196566858083bd1da4082b8c89e3fbcf5e2239347777614cac9355598491a");
  private byte[] dataHash;

  @Before
  public void setUp() throws NoSuchAlgorithmException {
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
    LibSecp256k1.secp256k1_ec_pubkey_serialize(
        LibSecp256k1.CONTEXT, recoveredKey, keySize, newPubKey, SECP256K1_EC_UNCOMPRESSED);

    Assert.assertArrayEquals(publicKey, recoveredKey.array());
  }
}
