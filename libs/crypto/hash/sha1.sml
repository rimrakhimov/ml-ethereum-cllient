use "libs/crypto/hash/hashSig";

local
  open Foreign

  val crypto_lib = loadLibrary "libs/crypto/hash/src/BRCrypto.so"
  val call = buildCall3((getSymbol crypto_lib "BRSHA1"),
                  (cArrayPointer cUchar, cByteArray, cUint),
                  cVoid)
in
  (* sha-1 - not recommended for cryptographic use *)
  structure Sha1 : HASH =
  struct
     (* internal function used to create an output buffer for foreign call *)
    fun createBuffer (size : int) = Array.array (size, 0w0 : Word8.word)

    local
      fun toList a = Array.foldr op:: [] a
    in
      fun arrayToWord8Vector a = Word8Vector.fromList (toList a)
    end

    val name = "SHA-1"

    val outputSize = 20
    val blockSize = 64

    fun hash (data) =
    let
      val buf = createBuffer (outputSize)
    in
      call (buf, data, Word8Vector.length data);
      arrayToWord8Vector buf
    end

  end
end
