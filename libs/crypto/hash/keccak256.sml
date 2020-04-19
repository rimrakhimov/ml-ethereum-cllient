use "libs/crypto/hash/hashSig";

local
  open Foreign

  val crypto_lib = loadLibrary "libs/crypto/src/BRCrypto.so"
  val call = buildCall3((getSymbol crypto_lib "BRKeccak256"),
                  (cArrayPointer cUchar, cByteArray, cUint),
                  cVoid)
in
   (* keccak-256: https://keccak.team/files/Keccak-submission-3.pdf *)
  structure Keccak256 : HASH =
  struct
     (* internal function used to create an output buffer for foreign call *)
    fun createBuffer (size : int) = Array.array (size, 0w0 : Word8.word)

    local
      fun toList a = Array.foldr op:: [] a
    in
      fun arrayToWord8Vector a = Word8Vector.fromList (toList a)
    end

    val name = "Keccak-256"

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
