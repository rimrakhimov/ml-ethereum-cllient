use "libs/crypto/hash/hashSig";

signature HMAC =
sig
  structure Hash : HASH
  val hmac : Word8Vector.vector -> Word8Vector.vector -> Word8Vector.vector
end

functor Hmac(Hash : HASH) : HMAC =
struct
  structure Hash = Hash

  local
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
    fun hmac key data =
    let
      val blockSize = Hash.blockSize

      val modifiedKey =
        if
          Word8Vector.length key > blockSize
        then
          rightPadVector (Hash.hash key, blockSize)
        else
          rightPadVector (key, blockSize)

      val s_i = Word8Vector.map (fn(x) => Word8.xorb (x, 0wx36)) modifiedKey
      val s_o = Word8Vector.map (fn(x) => Word8.xorb (x, 0wx5c)) modifiedKey
    in
      Hash.hash (Word8Vector.concat([
        s_o,
        Hash.hash (Word8Vector.concat ([s_i, data]))
      ]))
    end
  end
end
