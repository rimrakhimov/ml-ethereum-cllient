use "libs/crypto/hash/sha1";
use "libs/crypto/hash/sha256";
use "libs/crypto/hash/sha224";
use "libs/crypto/hash/sha384";
use "libs/crypto/hash/sha512";
use "libs/crypto/hash/ripemd160";
use "libs/crypto/hash/sha3_256";
use "libs/crypto/hash/keccak256";
use "libs/crypto/hash/md5";

structure Test =
struct
  exception Assert of string

  local
    val msg = Byte.stringToBytes "Hello"

    fun sha1TestHash () =
    let
      val expected = Word8Vector.fromList [
        0wxf7, 0wxff, 0wx9e, 0wx8b, 0wx7b, 0wxb2, 0wxe0, 0wx9b,
        0wx70, 0wx93, 0wx5a, 0wx5d, 0wx78, 0wx5e, 0wx0c, 0wxc5,
        0wxd9, 0wxd0, 0wxab, 0wxf0
      ]
      val res = Sha1.hash msg
    in
      if expected <> res
      then raise Assert "sha1 - hash"
      else print ("    sha1 successfully passed\n")
    end


    fun sha256TestHash () =
    let
      val expected = Word8Vector.fromList [
        0wx18, 0wx5f, 0wx8d, 0wxb3, 0wx22, 0wx71, 0wxfe, 0wx25,
        0wxf5, 0wx61, 0wxa6, 0wxfc, 0wx93, 0wx8b, 0wx2e, 0wx26,
        0wx43, 0wx06, 0wxec, 0wx30, 0wx4e, 0wxda, 0wx51, 0wx80,
        0wx07, 0wxd1, 0wx76, 0wx48, 0wx26, 0wx38, 0wx19, 0wx69
      ]
      val res = Sha256.hash msg
    in
      if expected <> res
      then raise Assert "sha256 - hash"
      else print ("    sha256 successfully passed\n")
    end


    fun sha224TestHash () =
    let
      val expected = Word8Vector.fromList [
        0wx41, 0wx49, 0wxda, 0wx18, 0wxaa, 0wx8b, 0wxfc, 0wx2b,
        0wx1e, 0wx38, 0wx2c, 0wx6c, 0wx26, 0wx55, 0wx6d, 0wx01,
        0wxa9, 0wx2c, 0wx26, 0wx1b, 0wx64, 0wx36, 0wxda, 0wxd5,
        0wxe3, 0wxbe, 0wx3f, 0wxcc
      ]
      val res = Sha224.hash msg
    in
      if expected <> res
      then raise Assert "sha224 - hash"
      else print ("    sha224 successfully passed\n")
    end


    fun sha384TestHash () =
    let
      val expected = Word8Vector.fromList [
        0wx35, 0wx19, 0wxfe, 0wx5a, 0wxd2, 0wxc5, 0wx96, 0wxef,
        0wxe3, 0wxe2, 0wx76, 0wxa6, 0wxf3, 0wx51, 0wxb8, 0wxfc,
        0wx0b, 0wx03, 0wxdb, 0wx86, 0wx17, 0wx82, 0wx49, 0wx0d,
        0wx45, 0wxf7, 0wx59, 0wx8e, 0wxbd, 0wx0a, 0wxb5, 0wxfd,
        0wx55, 0wx20, 0wxed, 0wx10, 0wx2f, 0wx38, 0wxc4, 0wxa5,
        0wxec, 0wx83, 0wx4e, 0wx98, 0wx66, 0wx80, 0wx35, 0wxfc
      ]
      val res = Sha384.hash msg
    in
      if expected <> res
      then raise Assert "sha384 - hash"
      else print ("    sha384 successfully passed\n")
    end


    fun sha512TestHash () =
    let
      val expected = Word8Vector.fromList [
        0wx36, 0wx15, 0wxf8, 0wx0c, 0wx9d, 0wx29, 0wx3e, 0wxd7,
        0wx40, 0wx26, 0wx87, 0wxf9, 0wx4b, 0wx22, 0wxd5, 0wx8e,
        0wx52, 0wx9b, 0wx8c, 0wxc7, 0wx91, 0wx6f, 0wx8f, 0wxac,
        0wx7f, 0wxdd, 0wxf7, 0wxfb, 0wxd5, 0wxaf, 0wx4c, 0wxf7,
        0wx77, 0wxd3, 0wxd7, 0wx95, 0wxa7, 0wxa0, 0wx0a, 0wx16,
        0wxbf, 0wx7e, 0wx7f, 0wx3f, 0wxb9, 0wx56, 0wx1e, 0wxe9,
        0wxba, 0wxae, 0wx48, 0wx0d, 0wxa9, 0wxfe, 0wx7a, 0wx18,
        0wx76, 0wx9e, 0wx71, 0wx88, 0wx6b, 0wx03, 0wxf3, 0wx15
      ]
      val res = Sha512.hash msg
    in
      if expected <> res
      then raise Assert "sha512 - hash"
      else print ("    sha512 successfully passed\n")
    end


    fun ripemd160TestHash () =
    let
      val expected = Word8Vector.fromList [
        0wxd4, 0wx44, 0wx26, 0wxac, 0wxa8, 0wxae, 0wx0a, 0wx69,
        0wxcd, 0wxbc, 0wx40, 0wx21, 0wxc6, 0wx4f, 0wxa5, 0wxad,
        0wx68, 0wxca, 0wx32, 0wxfe
      ]
      val res = Ripemd160.hash msg
    in
      if expected <> res
      then raise Assert "ripemd160 - hash"
      else print ("    ripemd160 successfully passed\n")
    end


    fun sha3_256TestHash () =
    let
      val expected = Word8Vector.fromList [
        0wx8c, 0wxa6, 0wx6e, 0wxe6, 0wxb2, 0wxfe, 0wx4b, 0wxb9,
        0wx28, 0wxa8, 0wxe3, 0wxcd, 0wx2f, 0wx50, 0wx8d, 0wxe4,
        0wx11, 0wx9c, 0wx08, 0wx95, 0wxf2, 0wx2e, 0wx01, 0wx11,
        0wx17, 0wxe2, 0wx2c, 0wxf9, 0wxb1, 0wx3d, 0wxe7, 0wxef
      ]
      val res = Sha3_256.hash msg
    in
      if expected <> res
      then raise Assert "sha3_256 - hash"
      else print ("    sha3_256 successfully passed\n")
    end


    fun keccak256TestHash () =
    let
      val expected = Word8Vector.fromList [
        0wx06, 0wxb3, 0wxdf, 0wxae, 0wxc1, 0wx48, 0wxfb, 0wx1b,
        0wxb2, 0wxb0, 0wx66, 0wxf1, 0wx0e, 0wxc2, 0wx85, 0wxe7,
        0wxc9, 0wxbf, 0wx40, 0wx2a, 0wxb3, 0wx2a, 0wxa7, 0wx8a,
        0wx5d, 0wx38, 0wxe3, 0wx45, 0wx66, 0wx81, 0wx0c, 0wxd2
      ]
      val res = Keccak256.hash msg
    in
      if expected <> res
      then raise Assert "keccak256 - hash"
      else print ("    keccak256 successfully passed\n")
    end


    fun md5TestHash () =
    let
      val expected = Word8Vector.fromList [
        0wx8b, 0wx1a, 0wx99, 0wx53, 0wxc4, 0wx61, 0wx12, 0wx96,
        0wxa8, 0wx27, 0wxab, 0wxf8, 0wxc4, 0wx78, 0wx04, 0wxd7
      ]
      val res = Md5.hash msg
    in
      if expected <> res
      then raise Assert "md5 - hash"
      else print ("    md5 successfully passed\n")
    end
  in
    fun testHash () =
    let
      val _ = print("'Hash Test' started:\n")
      val _ = sha1TestHash ()
      val _ = sha256TestHash ()
      val _ = sha224TestHash ()
      val _ = sha384TestHash ()
      val _ = sha512TestHash ()
      val _ = ripemd160TestHash ()
      val _ = sha3_256TestHash ()
      val _ = keccak256TestHash ()
      val _ = md5TestHash ()
    in
      print ("'Hash Test' successfully passed\n\n")
    end


    local
      fun sha1TestOutputSize () =
      let
        val expected = 20
        val res = Sha1.outputSize
      in
        if expected <> res
        then raise Assert "sha1 - output size"
        else print ("    sha1 successfully passed\n")
      end

      fun sha224TestOutputSize () =
      let
        val expected = 28
        val res = Sha224.outputSize
      in
        if expected <> res
        then raise Assert "sha224 - output size"
        else print ("    sha224 successfully passed\n")
      end

      fun sha256TestOutputSize () =
      let
        val expected = 32
        val res = Sha256.outputSize
      in
        if expected <> res
        then raise Assert "sha256 - output size"
        else print ("    sha256 successfully passed\n")
      end

      fun sha384TestOutputSize () =
      let
        val expected = 48
        val res = Sha384.outputSize
      in
        if expected <> res
        then raise Assert "sha384 - output size"
        else print ("    sha384 successfully passed\n")
      end

      fun sha512TestOutputSize () =
      let
        val expected = 64
        val res = Sha512.outputSize
      in
        if expected <> res
        then raise Assert "sha512 - output size"
        else print ("    sha512 successfully passed\n")
      end

      fun ripemd160TestOutputSize () =
      let
        val expected = 20
        val res = Ripemd160.outputSize
      in
        if expected <> res
        then raise Assert "ripemd160 - output size"
        else print ("    ripemd160 successfully passed\n")
      end

      fun sha3_256TestOutputSize () =
      let
        val expected = 32
        val res = Sha3_256.outputSize
      in
        if expected <> res
        then raise Assert "sha3_256 - output size"
        else print ("    sha3_256 successfully passed\n")
      end


      fun keccak256TestOutputSize () =
      let
        val expected = 32
        val res = Keccak256.outputSize
      in
        if expected <> res
        then raise Assert "keccak256 - output size"
        else print ("    keccak256 successfully passed\n")
      end

      fun md5TestOutputSize () =
      let
        val expected = 16
        val res = Md5.outputSize
      in
        if expected <> res
        then raise Assert "md5 - output size"
        else print ("    md5 successfully passed\n")
      end
    in
      fun testOutputSize () =
      let
        val _ = print("'Output Size Test' started:\n")
        val _ = sha1TestOutputSize ()
        val _ = sha256TestOutputSize ()
        val _ = sha224TestOutputSize ()
        val _ = sha384TestOutputSize ()
        val _ = sha512TestOutputSize ()
        val _ = ripemd160TestOutputSize ()
        val _ = sha3_256TestOutputSize ()
        val _ = keccak256TestOutputSize ()
        val _ = md5TestOutputSize ()
      in
        print ("'Output Size Test' successfully passed\n\n")
      end
    end

    local
      fun sha1TestBlockSize () =
      let
        val expected = 64
        val res = Sha1.blockSize
      in
        if expected <> res
        then raise Assert "sha1 - block size"
        else print ("    sha1 successfully passed\n")
      end

      fun sha224TestBlockSize () =
      let
        val expected = 64
        val res = Sha224.blockSize
      in
        if expected <> res
        then raise Assert "sha224 - block size"
        else print ("    sha224 successfully passed\n")
      end

      fun sha256TestBlockSize () =
      let
        val expected = 64
        val res = Sha256.blockSize
      in
        if expected <> res
        then raise Assert "sha256 - block size"
        else print ("    sha256 successfully passed\n")
      end

      fun sha384TestBlockSize () =
      let
        val expected = 128
        val res = Sha384.blockSize
      in
        if expected <> res
        then raise Assert "sha384 - block size"
        else print ("    sha384 successfully passed\n")
      end

      fun sha512TestBlockSize () =
      let
        val expected = 128
        val res = Sha512.blockSize
      in
        if expected <> res
        then raise Assert "sha512 - block size"
        else print ("    sha512 successfully passed\n")
      end

      fun ripemd160TestBlockSize () =
      let
        val expected = 64
        val res = Ripemd160.blockSize
      in
        if expected <> res
        then raise Assert "ripemd160 - block size"
        else print ("    ripemd160 successfully passed\n")
      end

      fun sha3_256TestBlockSize () =
      let
        val expected = 136
        val res = Sha3_256.blockSize
      in
        if expected <> res
        then raise Assert "sha3_256 - block size"
        else print ("    sha3_256 successfully passed\n")
      end

      fun keccak256TestBlockSize () =
      let
        val expected = 136
        val res = Keccak256.blockSize
      in
        if expected <> res
        then raise Assert "keccak256 - block size"
        else print ("    keccak256 successfully passed\n")
      end

      fun md5TestBlockSize () =
      let
        val expected = 64
        val res = Md5.blockSize
      in
        if expected <> res
        then raise Assert "md5 - block size"
        else print ("    md5 successfully passed\n")
      end
    in
      fun testBlockSize () =
      let
        val _ = print("'Block Size Test' started:\n")
        val _ = sha1TestBlockSize ()
        val _ = sha256TestBlockSize ()
        val _ = sha224TestBlockSize ()
        val _ = sha384TestBlockSize ()
        val _ = sha512TestBlockSize ()
        val _ = ripemd160TestBlockSize ()
        val _ = sha3_256TestBlockSize ()
        val _ = keccak256TestBlockSize ()
        val _ = md5TestBlockSize ()
      in
        print ("'Block Size Test' successfully passed\n\n")
      end
    end

    fun runAll () =
      (testHash(); testOutputSize(); testBlockSize())
  end
end
