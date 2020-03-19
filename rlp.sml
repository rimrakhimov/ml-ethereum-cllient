use "utils";
use "libs/PackWord";

structure Rlp =
  struct
    datatype RlpItem = RlpString of Word8Vector.vector
                     | RlpList of RlpItem list;

    structure Encoder =
      struct

        val emptyRlpString = Word8Array.vector(Word8Array.array (1, 0wx80));
        val emptyRlpList = Word8Array.vector(Word8Array.array (1, 0wxc0));

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

        fun encodeRlpString (RlpString(b)) =
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

        fun encodeRlpList (RlpList(l)) =
          let
            fun encodeRlpListItems ([], currentResult) =
                  currentResult
              | encodeRlpListItems ((item : RlpItem) :: ls, currentResult) =
                  let
                    val encodedItem = case item of
                                        RlpString (_) => encodeRlpString item
                                      | RlpList (_) => encodeRlpList item
                    val newResult = Word8Vector.concat [currentResult, encodedItem]
                  in
                    encodeRlpListItems (ls, newResult)
                  end

            val encodedItems = encodeRlpListItems (l, Word8Vector.fromList [])
            val len = Word8Vector.length encodedItems
            val header = encodeHeader (len, true)
          in
            Word8Vector.concat [header, encodedItems]
          end

        fun encodeString s =
          encodeRlpString (RlpString (Byte.stringToBytes s))

        fun encodeWord8 w =
          let
            val arr = Word8Array.array (PackWord8Big.bytesPerElem, 0w0)
          in
            PackWord8Big.update (arr, 0, Word8.toLarge w);
            encodeRlpString (RlpString (Word8Array.vector arr))
          end

        fun encodeWord16 w =
          let
            val arr = Word8Array.array (PackWord16Big.bytesPerElem, 0w0)
          in
            PackWord16Big.update (arr, 0, Word16.toLarge w);
            encodeRlpString (RlpString (Word8Array.vector arr))
          end

         fun encodeWord32 w =
          let
            val arr = Word8Array.array (PackWord32Big.bytesPerElem, 0w0)
          in
            PackWord32Big.update (arr, 0, Word32.toLarge w);
            encodeRlpString (RlpString (Word8Array.vector arr))
          end

         fun encodeWord64 w =
          let
            val arr = Word8Array.array (PackWord64Big.bytesPerElem, 0w0)
          in
            PackWord64Big.update (arr, 0, Word64.toLarge w);
            encodeRlpString (RlpString (Word8Array.vector arr))
          end
    end

    structure Decoder =
      struct
        local
          fun getPackerSubVec size =
            case size of
                 1 => PackWord8Big.subVec  |
                 2 => PackWord16Big.subVec |
                 3 => PackWord24Big.subVec |
                 4 => PackWord32Big.subVec |
                 5 => PackWord40Big.subVec |
                 6 => PackWord48Big.subVec |
                 7 => PackWord56Big.subVec |
                 8 => PackWord64Big.subVec |
                  (* is not raised now, as the maximum
                      Word8Vector length is limited by 8 bytes *)
                 _ => raise Overflow
          in
            fun getLength (b, isList) =
              let
                val base = if isList then 0xc0 else 0x80
                val prefix = Word8.toInt (Word8Vector.sub(b, 0))
              in
                if prefix <= base + 55
                  then
                    {offset = 1, len = prefix - base}
                  else
                    let
                      val lenSize = prefix - (base + 55)
                      val packerSubVec = getPackerSubVec lenSize

                      val sizeBytes = Word8VectorSlice.vector (
                                          Word8VectorSlice.slice(b, 1, SOME lenSize))
                      val len = Int.fromLarge (LargeWord.toLargeInt
                                                    (packerSubVec (sizeBytes, 0)))
                    in
                      {offset = 1 + lenSize, len = len}
                    end
              end
          end

        local
          val base = 0wx80
        in
          fun decodeRlpString b =
            let
              val prefix = Word8Vector.sub (b, 0)
            in
              if Word8Vector.length b = 1 andalso prefix < base
                then  (* data is the string itself *)
                  RlpString (b)
                else
                  let
                    val len_off = getLength (b, false)
                    val offset = #offset len_off
                    val len = #len len_off
                  in
                    RlpString (Word8VectorSlice.vector (
                                  Word8VectorSlice.slice(b, offset, SOME len)))
                  end
            end
        end

        fun decodeRlpList b =


      end
end
