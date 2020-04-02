use "utils";
use "libs/PackWord";

structure Rlp =
  struct
      (* boolean specifies whether item is already   *)
    datatype rlpItem = RlpString of Word8Vector.vector
                     | RlpList of rlpItem list;

      (* Rlp encoded vector, offset of data beginning, len of data *)
    datatype rlpResult = RlpResult of {data : Word8Vector.vector,
                                       offset : Word8.word,
                                       len : Word64.word};

    fun getRlpResultData (RlpResult(result)) = #data result
    fun getRlpResultOffset (RlpResult(result)) = #offset result
    fun getRlpResultLength (RlpResult(result)) = #len result


    structure Encoder =
      struct

        (* val emptyRlpString = RlpResult(Word8Array.vector(Word8Array.array (1, 0wx80))); *)
        (* val emptyRlpList = RlpResult(Word8Array.vector(Word8Array.array (1, 0wxc0))); *)

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
                RlpResult({
                  data = Word8Vector.fromList [Word8Vector.sub(b, 0)],
                  offset = 0w0,
                  len = Word64.fromInt len
                })
              else
                let
                  val header = encodeHeader (len, false)
                in
                  RlpResult({
                    data = Word8Vector.concat [header, b],
                    offset = Word8.fromInt (Word8Vector.length header),
                    len = Word64.fromInt len
                  })
                end
          end

    (* none of the items are assumed to be encoded prior *)
        fun encodeRlpList (RlpList(l)) =
          let
            (* returns vector instead of rlpResult
             *  as vector is used by encodeRlpList function *)
            fun encodeRlpListItems ([], currentResultVec) =
                  currentResultVec
              | encodeRlpListItems ((item : rlpItem) :: ls, currentResultVec) =
                  let
                    val encodedItem = case item of
                                        RlpString (_) => encodeRlpString item
                                      | RlpList (_) => encodeRlpList item
                    val encodedItemData = getRlpResultData encodedItem
                    val newResultVec = Word8Vector.concat [currentResultVec, encodedItemData]
                  in
                    encodeRlpListItems (ls, newResultVec)
                  end

            val encodedItemsVec = encodeRlpListItems (l, Word8Vector.fromList [])
            val len = Word8Vector.length encodedItemsVec
            val header = encodeHeader (len, true)
          in
            RlpResult({
              data = Word8Vector.concat [header, encodedItemsVec],
              offset = Word8.fromInt (Word8Vector.length header),
              len = Word64.fromInt len
            })
          end

        (* the whole content of the list is assumed to be rlp encoded *)
        fun encodeRlpResultsList (l : rlpResult list) =
          let
            fun concatenateItems ([], currentResult) =
                  currentResult
              | concatenateItems (item :: ls, currentResult) =
                  let val itemData = getRlpResultData(item)
                  in
                    concatenateItems (ls, Word8Vector.concat [currentResult, itemData])
                  end

            val allItems = concatenateItems(l, Word8Vector.fromList [])
            val len = Word8Vector.length allItems
            val header = encodeHeader (len, true)
          in
            RlpResult({
              data = Word8Vector.concat [header, allItems],
              offset = Word8.fromInt (Word8Vector.length header),
              len = Word64.fromInt len
            })
          end

        fun encodeString s =
          encodeRlpString (RlpString (Byte.stringToBytes s))

        local
          fun normalizeWord (w : Word8Vector.vector) =
            let
              val wordLen = Word8Vector.length w

              fun getNonZeroIndex (currentIndex) =
                if
                  currentIndex < wordLen
                then
                  if
                    Word8Vector.sub (w, currentIndex) <> 0wx0
                  then
                    currentIndex
                  else
                    getNonZeroIndex (currentIndex + 1)
                else
                  currentIndex + 1    (* all elements are zeros *)

              val nonZeroIndex = getNonZeroIndex 0
            in
              if
                nonZeroIndex < wordLen
              then
                Word8VectorSlice.vector (Word8VectorSlice.slice (w, nonZeroIndex, NONE))
              else    (* all elements are zeros *)
                Word8Vector.fromList [0wx0]
            end
        in
          fun encodeWord (w : Word8Vector.vector) =
            encodeRlpString (RlpString (normalizeWord w))
        end



        fun encodeWord8 w =
          let
            val arr = Word8Array.array (PackWord8Big.bytesPerElem, 0w0)
          in
            PackWord8Big.update (arr, 0, Word8.toLarge w);
            encodeWord (Word8Array.vector arr)
          end

        fun encodeWord16 w =
          let
            val arr = Word8Array.array (PackWord16Big.bytesPerElem, 0w0)
          in
            PackWord16Big.update (arr, 0, Word16.toLarge w);
            encodeWord (Word8Array.vector arr)
          end

         fun encodeWord32 w =
          let
            val arr = Word8Array.array (PackWord32Big.bytesPerElem, 0w0)
          in
            PackWord32Big.update (arr, 0, Word32.toLarge w);
            encodeWord (Word8Array.vector arr)
          end

         fun encodeWord64 w =
          let
            val arr = Word8Array.array (PackWord64Big.bytesPerElem, 0w0)
          in
            PackWord64Big.update (arr, 0, Word64.toLarge w);
            encodeWord (Word8Array.vector arr)
          end
    end

(*    structure Decoder =
      struct
        exception WrongRlpFormat of string;

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

          fun decodeStringLength input =
            let
              val base = 0wx80
              val inLen = Word8Vector.length input
              val prefix = Word8Vector.sub (input, 0)
            in
              if
                prefix < base
              then
                {len = 1, offset = 0, isList = false}

              else
                if
                  prefix <= (base + 0w55)  andalso inLen > Word8.toInt (prefix - base)
                then
                  let
                    val strLen = Word8.toInt (prefix - base)
                  in
                    if
                      strLen = 1 andalso Word8Vector.sub(input, 1) < base
                    then
                      raise WrongRlpFormat "Single byte below 128 must be encoded as itself"
                    else
                      {len = strLen, offset = 1, isList = false}
                  end

                else
                  if
                    prefix < (base + 0wx40) andalso inLen > Word8.toInt (prefix - (base + 0w55))
                  then
                    let
                      val lenSize = Word8.toInt (prefix - (base + 0w55))
                      val packerSubVec = getPackerSubVec lenSize

                      val sizeBytes = Word8VectorSlice.vector (
                        Word8VectorSlice.slice(input, 1, SOME lenSize)
                      )
                      val len = Int.fromLarge(
                        LargeWord.toLargeInt (packerSubVec (sizeBytes, 0))
                      )
                    in
                      if
                        inLen > Word8.toInt (prefix - (base + 0w55)) + len
                      then
                        if
                          Word8Vector.sub(input, 1) = 0w0
                        then
                          raise WrongRlpFormat "Multi-byte length must have no leading zero"
                        else
                          if
                            len < 56
                          then
                            raise WrongRlpFormat "Length below 56 must be encoded in one byte"
                          else
                            {len = len, offset = 1 + lenSize, isList = false}
                      else
                        raise WrongRlpFormat "Input don't conform RLP encoding form"
                    end

                  else
                    raise WrongRlpFormat "Input don't conform RLP encoding form"
            end

          fun decodeListLength input =
            let
              val base = 0wxc0
              val inLen = Word8Vector.length input
              val prefix = Word8Vector.sub (input, 0)
            in
              if
                prefix <= (base + 0w55) andalso inLen > Word8.toInt (prefix - base)
              then
                {len = Word8.toInt (prefix - base), offset = 1, isList = true}

              else
                if
                  prefix < (base + 0wx40) andalso inLen > Word8.toInt (prefix - (base + 0w55))
                then
                  let
                    val lenSize = Word8.toInt (prefix - (base + 0w55))
                    val packerSubVec = getPackerSubVec lenSize

                    val sizeBytes = Word8VectorSlice.vector (
                      Word8VectorSlice.slice(input, 1, SOME lenSize)
                    )
                    val len = Int.fromLarge(
                      LargeWord.toLargeInt (packerSubVec (sizeBytes, 0))
                    )
                  in
                    if
                      inLen > Word8.toInt (prefix - (base + 0w55)) + len
                    then
                      if
                        Word8Vector.sub(input, 1) = 0w0
                      then
                        raise WrongRlpFormat "Multi-byte length must have no leading zero"
                      else
                        if
                          len < 56
                        then
                          raise WrongRlpFormat "Length below 56 must be encoded in one byte"
                        else
                          {len = len, offset = 1 + lenSize, isList = true}
                    else
                      raise WrongRlpFormat "Input don't conform RLP encoding form"
                  end

              else
                raise WrongRlpFormat "Input don't conform RLP encoding form"
            end

          val emptyVector = Word8Vector.fromList []

        in
          fun decodeLength (emptyArray) =
                (* should not be raised as function is not
                    called for empty vectors *)
                raise WrongRlpFormat "Input is null"
            | decodeLength (input) =
                let
                  val prefix = Word8Vector.sub(input, 0)
                in
                  if
                    prefix < 0wxc0
                  then
                    decodeStringLength input
                  else
                    decodeListLength input
                end
        end

        fun formRlpResult (input : Word8Vector) =


//        local
          val emptyVector = Word8Vector.fromList []
        in
          fun rlpDecode (emptyVector) =
                raise WrongRlpFormat "Input is null"
            | rlpDecode (input) =
                let
                  val header = decodeLength (input)
                  val len = #len header
                  val offset = #offset header
                  val isList = #isList header

                  val encodedItem = Word8VectorSlice.vector (
                        Word8VectorSlice.slice (input, offset, SOME len)
                      )
                  val remainedInput = Word8VectorSlice.vector(
                        Word8VectorSlice.slice (input, offset + len, NONE)
                      )

                  fun rlpDecodeString (input) =
                    RlpString (input)


                  fun rlpDecodeList (input) =
                    RlpList (rlpDecode (input))

                in
                  if
                    isList
                  then

                  else
                    rlpDecodeString (encodedItem)
                end //



//              | getLength
              let
                val len = Word8Vector.length b
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
          end //

//        local
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
          end //

//        local
          val base = 0wx80
        in
          fun decodeRlpStringInternal b =
            let
              val prefix = Word8Vector.sub (b, 0)
            in
              if Word8Vector.length b = 1 andalso prefix < base
                then  (* data is the string itself *)
                { encodedString = RlpString (b),
                  remaindeBytes = Word8VectorSlice.vector (
                                 Word8VectorSlice.slice(b, ))
                else
                  let
                    val len_off = getLength (b, false)
                    val offset = #offset len_off
                    val len = #len len_off
                  in
                    { encodedString = RlpString (Word8VectorSlice.vector (
                                     Word8VectorSlice.slice(b, offset, SOME len))),
                      remainedBytes = Word8VectorSlice.vector (
                                     Word8VectorSlice.slice(b, offset + len, NONE))
                    }
                  end
            end
        end

        fun decodeRlpString b =
          #encodedString (decodeRlpString b) //

//        local
          val base = 0wxc0
        in
          fun decodeRlpList b =
            let
              fun decodeRlpListItem (bRemainder, decodedList) =
                let
                  val isList =
              val len_off = getLength (b, true) //

      end *)
end
