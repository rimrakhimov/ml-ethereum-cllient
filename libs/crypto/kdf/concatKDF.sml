use "libs/crypto/kdf/kdfSig";
use "libs/crypto/hash/hashSig";
use "utils";

functor ConcatKDF (Hash : HASH) : KDF =
struct
  exception Kdf of string

  val hash = Hash.name
  val hashlen = Hash.outputSize

  fun kdf (Z, keydatalen, otherInfo) =
  let
    val reps = Real.ceil (Real.fromInt(keydatalen) / Real.fromInt(hashlen))
    val _ = if reps > 4294967295 (* 2^32 - 1 *)
            then raise Kdf "Requested length of key is too big"
            else ()

    val i = ref 0
    fun loop (counter, res) =
      if
        (!i) < reps
      then
        let
          val counterVector = Utils.word32ToWord8Vector counter
          val hash = Hash.hash (Word8Vector.concat [counterVector, Z, otherInfo])
          val newRes = Word8Vector.concat [res, hash]
        in
          i := (!i) + 1;
          loop (counter + 0w1, newRes)
        end
      else
        Word8VectorSlice.vector (
          Word8VectorSlice.slice (res, 0, SOME keydatalen)
        )
  in
    loop (0wx1 : Word32.word, Word8Vector.fromList [])
  end

end
