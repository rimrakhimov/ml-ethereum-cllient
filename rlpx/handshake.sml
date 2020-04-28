use "libs/crypto/kdf/concatKDF";
use "libs/crypto/hash/keccak256";
use "libs/secp256k1/secp256k1";
use "utils";

structure Handshake =
struct
  structure Hash = Keccak256

  fun computeSharedSecret (ephemeralLocalPrivkey, remotePubkey) =
    Utils.takeVectorSlice (
      Secp256k1.ecdsaPubkeyMul remotePubkey ephemeralLocalPrivkey, 1, SOME 32
    )
     (* if Secp256k1 has not been started yet, start and try again *)
    handle Fail ex => (
      Secp256k1.start();
      Secp256k1.ecdsaPubkeyMul remotePubkey ephemeralLocalPrivkey
    )

  local
    structure Kdf = ConcatKDF(Hash)
  in
    fun deriveKeyMaterials (ephemeralLocalPrivkey, remotePubkey) =
    let
      val sharedSecret = computeSharedSecret (ephemeralLocalPrivkey, remotePubkey)
      val keyMaterial = Kdf.kdf (sharedSecret, 32, Word8Vector.fromList [])

      val encKey = Utils.takeVectorSlice (keyMaterial, 0, SOME 16)
      val authKey = Utils.takeVectorSlice (keyMaterial, 16, SOME 16)
    in
      {encKey = encKey, authKey = authKey}
    end
  end

end
