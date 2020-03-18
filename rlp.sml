use "utils";
use "libs/PackWord";

fun word32ToWord8Vector (item : Word32.word) =
  let
    val arr = Word8Array.array(PackWord32Big.bytesPerElem, 0w0);
  in
    PackWord32Big.update (arr, 0, Word32.toLargeWord item);
    Word8Array.vector arr
  end;

structure Encoder =
  struct
    val emptyString = Word8Array.vector(Word8Array.array (1, 0wx80));
    val emptyList = Word8Array.vector(Word8Array.array (1, 0wxc0));

    local
      fun getPacker size =
        case size of
             1 => PackWord8Big
             2 => PackWord16Big
             3 => PackWord24Big
             4 => PackWord32Big
             5 => PackWord40Big
             6 => PackWord48Big
             7 => PackWord56Big
             8 => PackWord64Big
      in
        fun encodeBytesHeader (len : int) =
          let
            val lenSize = Utils.getUIntSize(len)
            val base = Word8Vector.fromList [Word8.fromInt(0x80 + lenSize)]
            val packer = getPacker lenSize
            val arr = Word8Array.array (packer.bytesPerElem, 0w0)
            packer.update (arr, 0)
      in


            Word8Vector.concat [base, PackWord.])
      end

    fun encodeBytes (b : Word8Vector) =
      let
        len = Word8Vector.length b
      in
        if len = 1 andalso Word8Vector.sub(b, 1) < 0wx80
        then Word8Vector.fromList [Word8Vector.sub(b, 1)]
        else
          let
            val lenSize = Utils.getUIntSize(len)
          in
            b
          end
      end

  end;

