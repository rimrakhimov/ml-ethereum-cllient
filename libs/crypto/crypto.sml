signature CRYPTO =
sig
  val sha1 : Word8Vector.vector -> Word8Vector.vector;
  val sha256 : Word8Vector.vector -> Word8Vector.vector;
  val sha224 : Word8Vector.vector -> Word8Vector.vector;
  val sha256_2 : Word8Vector.vector -> Word8Vector.vector;
  val sha384 : Word8Vector.vector -> Word8Vector.vector;
  val sha512 : Word8Vector.vector -> Word8Vector.vector;
  val rmd160 : Word8Vector.vector -> Word8Vector.vector;
  val hash160 : Word8Vector.vector -> Word8Vector.vector;
  val sha3_256 : Word8Vector.vector -> Word8Vector.vector;
  val keccak256 : Word8Vector.vector -> Word8Vector.vector;
  val md5 : Word8Vector.vector -> Word8Vector.vector;
end

local
  open Foreign

  val keccak_lib = loadLibrary "libs/keccak/BRCrypto.so"

  val sha1Call = buildCall3((getSymbol keccak_lib "BRSHA1"),
                            (cArrayPointer cUchar, cByteArray, cUint),
                            cVoid)

  val sha256Call = buildCall3((getSymbol keccak_lib "BRSHA256"),
                            (cArrayPointer cUchar, cByteArray, cUint),
                            cVoid)

  val sha224Call = buildCall3((getSymbol keccak_lib "BRSHA224"),
                            (cArrayPointer cUchar, cByteArray, cUint),
                            cVoid)

  val sha256_2Call = buildCall3((getSymbol keccak_lib "BRSHA256_2"),
                            (cArrayPointer cUchar, cByteArray, cUint),
                            cVoid)

  val sha384Call = buildCall3((getSymbol keccak_lib "BRSHA384"),
                            (cArrayPointer cUchar, cByteArray, cUint),
                            cVoid)

  val sha512Call = buildCall3((getSymbol keccak_lib "BRSHA512"),
                            (cArrayPointer cUchar, cByteArray, cUint),
                            cVoid)

  val rmd160Call = buildCall3((getSymbol keccak_lib "BRRMD160"),
                            (cArrayPointer cUchar, cByteArray, cUint),
                            cVoid)

  val hash160Call = buildCall3((getSymbol keccak_lib "BRHash160"),
                            (cArrayPointer cUchar, cByteArray, cUint),
                            cVoid)

  val sha3_256Call = buildCall3((getSymbol keccak_lib "BRSHA3_256"),
                            (cArrayPointer cUchar, cByteArray, cUint),
                            cVoid)

  val keccak256Call = buildCall3((getSymbol keccak_lib "BRKeccak256"),
                                 (cArrayPointer cUchar, cByteArray, cUint),
                                 cVoid)

  val md5Call = buildCall3((getSymbol keccak_lib "BRMD5"),
                            (cArrayPointer cUchar, cByteArray, cUint),
                            cVoid)


in
  structure Crypto :CRYPTO =
  struct

    fun createBuffer (size : int) = Array.array (size, 0w0 : Word8.word)

    local
      fun toList a = Array.foldr op:: [] a
    in
      fun arrayToWord8Vector a = Word8Vector.fromList (toList a)
    end

    fun hash (call, bufSize) data =
    let
      val buf = createBuffer (bufSize)
    in
      call(buf, data, Word8Vector.length data);
      arrayToWord8Vector buf
    end

     (* sha-1 - not recommended for cryptographic use *)
    fun sha1 (data) = hash (sha1Call, 20) data

    fun sha256 (data) = hash (sha256Call, 32) data

    fun sha224 (data) = hash (sha224Call, 28) data

     (* double-sha-256 = sha-256(sha-256(x)) *)
    fun sha256_2 (data) = hash (sha256_2Call, 32) data

    fun sha384 (data) = hash (sha384Call, 48) data

    fun sha512 (data) = hash (sha512Call, 64) data

     (* ripemd-160: http://homes.esat.kuleuven.be/~bosselae/ripemd160.html *)
    fun rmd160 (data) = hash (rmd160Call, 20) data

     (* bitcoin hash-160 = ripemd-160(sha-256(x)) *)
    fun hash160 (data) = hash (hash160Call, 20) data

     (* sha3-256: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf *)
    fun sha3_256 (data) = hash (sha3_256Call, 32) data

     (* keccak-256: https://keccak.team/files/Keccak-submission-3.pdf *)
    fun keccak256 (data) = hash (keccak256Call, 32) data

     (* md5 - for non-cryptographic use only *)
    fun md5 (data) = hash (md5Call, 16) data

  end
end
