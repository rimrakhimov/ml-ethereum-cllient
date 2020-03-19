use "utils";
use "libs/PackWord";

structure Encoder =
  struct
    val emptyString = Word8Array.vector(Word8Array.array (1, 0wx80));
    val emptyList = Word8Array.vector(Word8Array.array (1, 0wxc0));

    local
      fun getPackerUpdater size =
        case size of
             1 => PackWord8Big.update  |
             2 => PackWord16Big.update |
             3 => PackWord24Big.update |
             4 => PackWord32Big.update |
             5 => PackWord40Big.update |
             6 => PackWord48Big.update |
             7 => PackWord56Big.update |
             8 => PackWord64Big.update |
              (* is not raised now, as the maximum
                  Word8Vector length is limited by 8 bytes *)
             _ => raise Overflow
      in
        fun encodeBytesHeader (len : int) =
          if len < 56
            then
              Word8Vector.fromList [Word8.fromInt (0x80 + len)]
            else
              let
                val lenSize = Utils.getUIntSize(len)
                val base = Word8Vector.fromList [Word8.fromInt(0xb7 + lenSize)]
                val packerUpdater = getPackerUpdater lenSize
                val arr = Word8Array.array (lenSize, 0w0)
                val fromIntToLargeWord = Word64.toLarge o Word64.fromInt
              in
                packerUpdater (arr, 0, fromIntToLargeWord len);
                Word8Vector.concat [base, Word8Array.vector arr]
              end
      end

    fun encodeBytes (b : Word8Vector.vector) =
      let
        val len = Word8Vector.length b
      in
        if len = 1 andalso Word8Vector.sub(b, 0) < 0wx80
          then
            Word8Vector.fromList [Word8Vector.sub(b, 0)]
          else
            let
              val header = encodeBytesHeader len
            in
              Word8Vector.concat [header, b]
            end
      end

    fun encodeList (l : Word8Vector.vector list) =
      1

  end;

