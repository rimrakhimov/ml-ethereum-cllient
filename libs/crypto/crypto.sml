signature CRYPTO =
sig
  eqtype hash_alg
  val SHA1      : hash_alg
  val SHA256    : hash_alg
  val SHA224    : hash_alg
  val SHA384    : hash_alg
  val SHA512    : hash_alg
  val RIPEMD160 : hash_alg
  val SHA3_256  : hash_alg
  val KECCAK256 : hash_alg
  val MD5       : hash_alg


  val sha1 : Word8Vector.vector -> Word8Vector.vector
  val sha256 : Word8Vector.vector -> Word8Vector.vector
  val sha224 : Word8Vector.vector -> Word8Vector.vector
  val sha256_2 : Word8Vector.vector -> Word8Vector.vector
  val sha384 : Word8Vector.vector -> Word8Vector.vector
  val sha512 : Word8Vector.vector -> Word8Vector.vector
  val ripemd160 : Word8Vector.vector -> Word8Vector.vector
  val hash160 : Word8Vector.vector -> Word8Vector.vector
  val sha3_256 : Word8Vector.vector -> Word8Vector.vector
  val keccak256 : Word8Vector.vector -> Word8Vector.vector
  val md5 : Word8Vector.vector -> Word8Vector.vector

  val hmac : hash_alg -> Word8Vector.vector -> Word8Vector.vector ->
         Word8Vector.vector

  structure HMAC_DRNG :
  sig
    type hmac_drng

    val init : hash_alg * Word8Vector.vector * Word8Vector.vector *
      Word8Vector.vector -> hmac_drng

    val reseed : hmac_drng * Word8Vector.vector * Word8Vector.vector -> unit

    val generate : hmac_drng * int * Word8Vector.vector -> Word8Vector.vector

  end

end

local
  open Foreign

  val keccak_lib = loadLibrary "libs/crypto/BRCrypto.so"

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

  val ripemd160Call = buildCall3((getSymbol keccak_lib "BRRMD160"),
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
  structure Crypto :> CRYPTO =
  struct

     (* internal function used to create an output buffer for foreign call *)
    fun createBuffer (size : int) = Array.array (size, 0w0 : Word8.word)

    local
      fun toList a = Array.foldr op:: [] a
    in
      fun arrayToWord8Vector a = Word8Vector.fromList (toList a)
    end


     (* internal function used to hash data with specified hash function *)
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
    fun ripemd160 (data) = hash (ripemd160Call, 20) data

     (* bitcoin hash-160 = ripemd-160(sha-256(x)) *)
    fun hash160 (data) = hash (hash160Call, 20) data

     (* sha3-256: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf *)
    fun sha3_256 (data) = hash (sha3_256Call, 32) data

     (* keccak-256: https://keccak.team/files/Keccak-submission-3.pdf *)
    fun keccak256 (data) = hash (keccak256Call, 32) data

     (* md5 - for non-cryptographic use only *)
    fun md5 (data) = hash (md5Call, 16) data

     (* to be able to define hash function to be used in HMAC *)
    datatype hash_alg = SHA1 | SHA256 | SHA224 |
                        SHA384 | SHA512 | RIPEMD160 |
                        SHA3_256 | KECCAK256 | MD5

    fun getHashFunction (algo : hash_alg) =
      case algo of
           SHA1 => sha1 |
           SHA256 => sha256 |
           SHA224 => sha224 |
           SHA384 => sha384 |
           SHA512 => sha512 |
           RIPEMD160 => ripemd160 |
           SHA3_256 => sha3_256 |
           KECCAK256 => keccak256 |
           MD5 => md5

    local
      fun getHashFunctionBlockSize (algo : hash_alg) =
        case algo of
             SHA1 => 64 |
             SHA256 => 64 |
             SHA224 => 64 |
             SHA384 => 128 |
             SHA512 => 128 |
             RIPEMD160 => 64 |
             SHA3_256 => 136 |
             KECCAK256 => 136 |
             MD5 => 64

      fun rightPadVector (v, size) =
      let
        val vSize = Word8Vector.length v
        val toPad = size - vSize
      in
        if
          toPad >= 0
        then
          Word8Vector.concat [v, Word8Array.vector (Word8Array.array (toPad, 0w0))]
        else
           (* must not be raised, as the size should be checked before the call *)
          raise Size
      end
    in
      fun hmac (algo : hash_alg) key data =
      let
        val blockSize = getHashFunctionBlockSize algo
        val hashFunction = getHashFunction algo

        val modifiedKey =
          if
            Word8Vector.length key > blockSize
          then
            rightPadVector (hashFunction key, blockSize)
          else
            rightPadVector (key, blockSize)

        val s_i = Word8Vector.map (fn(x) => Word8.xorb (x, 0wx36)) modifiedKey
        val s_o = Word8Vector.map (fn(x) => Word8.xorb (x, 0wx5c)) modifiedKey
      in
        hashFunction (Word8Vector.concat([
          s_o,
          hashFunction (Word8Vector.concat ([s_i, data]))
        ]))
      end
    end

    structure HMAC_DRNG =
    struct
      datatype hmac_drng = DRNG of hash_alg * Word8Vector.vector ref * Word8Vector.vector ref

      fun getHashFunctionOutputSize (algo : hash_alg) =
        case algo of
             SHA1 => 20 |
             SHA256 => 32 |
             SHA224 => 28 |
             SHA384 => 48 |
             SHA512 => 64 |
             RIPEMD160 => 20 |
             SHA3_256 => 32 |
             KECCAK256 => 32 |
             MD5 => 16


        (* Internal function used to update the internal state of DRNG.
         *  Corresponds to HMAC_DRBG_Update in NIST specification *)
      fun update(DRNG(algo, K, V), data) =
      let
        fun update_K_V (K, V, padByte) =
        let
          val _ = K := hmac algo (!K) (Word8Vector.concat [!V, Word8Vector.fromList[padByte], data])
          val _ = V := hmac algo (!K) (!V)
        in
          ()
        end
      in
        update_K_V (K, V, 0wx00);
        if
          Word8Vector.length data > 0
        then
          update_K_V (K, V, 0wx01)
        else
          ()
      end



      fun init (algo : hash_alg, entropy, nonce, ps) =
      let
        val seed = Word8Vector.concat [entropy, nonce, ps]
        val K = ref (Word8Array.vector(
          Word8Array.array(getHashFunctionOutputSize algo, 0w0)
        ))
        val V = ref (Word8Array.vector(
          Word8Array.array(getHashFunctionOutputSize algo, 0w1)
        ))
        val drng = DRNG(algo, K, V)
      in
        update(drng, seed);
        drng
      end

      fun reseed (drng, entropy, add_input) =
      let
        val seed = Word8Vector.concat [entropy, add_input]
      in
        update(drng, seed)
      end

      fun generate (drng, out_len, add_input) =
      let
        val _ = if Word8Vector.length add_input > 0
                then update(drng, add_input)
                else ()
        val DRNG(alg, ref key, V) = drng
        val h = hmac alg key
        fun loop (res) =
          if
            Word8Vector.length res < out_len
          then
            let
              val _ = V := h (!V)
            in
              loop (Word8Vector.concat [res, (!V)])
            end
          else
            Word8VectorSlice.vector (Word8VectorSlice.slice (res, 0, SOME out_len))
        val res = loop (Word8Vector.fromList [])
      in
        update(drng, add_input);
        res
      end

    end

  end
end
