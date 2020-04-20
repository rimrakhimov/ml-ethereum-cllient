use "libs/crypto/hash/hashSig";

local
  open Foreign

  val crypto_lib = loadLibrary "libs/crypto/hash/src/BRCrypto.so"
  val call = buildCall3((getSymbol crypto_lib "BRSHA3_256"),
                  (cArrayPointer cUchar, cByteArray, cUint),
                  cVoid)
in
   (* sha3-256: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf *)
  structure Sha3_256 : HASH =
  struct
     (* internal function used to create an output buffer for foreign call *)
    fun createBuffer (size : int) = Array.array (size, 0w0 : Word8.word)

    local
      fun toList a = Array.foldr op:: [] a
    in
      fun arrayToWord8Vector a = Word8Vector.fromList (toList a)
    end

    val name = "SHA3-256"

    val outputSize = 32
    val blockSize = 136

    fun hash (data) =
    let
      val buf = createBuffer (outputSize)
    in
      call (buf, data, Word8Vector.length data);
      arrayToWord8Vector buf
    end

  end
end
