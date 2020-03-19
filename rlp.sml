use "utils";
use "libs/PackWord";

structure Encoder =
  struct
    datatype RLPItem = RLPString of Word8Vector.vector
                     | RLPList of RLPItem list;

    val emptyRLPString = Word8Array.vector(Word8Array.array (1, 0wx80));
    val emptyRLPList = Word8Array.vector(Word8Array.array (1, 0wxc0));

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
        fun encodeHeader (len : int, isList : bool) =
          let
            val base = if isList then 0xc0 else 0x80
          in
            if len < 56
              then
                Word8Vector.fromList [Word8.fromInt (base + len)]
              else
                let
                  val lenSize = Utils.getUIntSize(len)
                  val prefix = Word8Vector.fromList [Word8.fromInt(base + 55 + lenSize)]
                  val packerUpdater = getPackerUpdater lenSize
                  val arr = Word8Array.array (lenSize, 0w0)
                  val fromIntToLargeWord = Word64.toLarge o Word64.fromInt
                in
                  packerUpdater (arr, 0, fromIntToLargeWord len);
                  Word8Vector.concat [prefix, Word8Array.vector arr]
                end
          end
      end

    fun encodeRLPString (RLPString(b)) =
      let
        val len = Word8Vector.length b
      in
        if len = 1 andalso Word8Vector.sub(b, 0) < 0wx80
          then
            Word8Vector.fromList [Word8Vector.sub(b, 0)]
          else
            let
              val header = encodeHeader (len, false)
            in
              Word8Vector.concat [header, b]
            end
      end

    fun encodeRLPList (RLPList(l)) =
      let
        fun encodeRLPListItems ([], currentResult) =
              currentResult
          | encodeRLPListItems ((item : RLPItem) :: ls, currentResult) =
              let
                val encodedItem = case item of
                                    RLPString (_) => encodeRLPString item
                                  | RLPList (_) => encodeRLPList item
                val newResult = Word8Vector.concat [currentResult, encodedItem]
              in
                encodeRLPListItems (ls, newResult)
              end

        val encodedItems = encodeRLPListItems (l, Word8Vector.fromList [])
        val len = Word8Vector.length encodedItems
        val header = encodeHeader (len, true)
      in
        Word8Vector.concat [header, encodedItems]
      end

end
