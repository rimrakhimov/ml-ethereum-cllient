local
  fun getData (a : int, b : int) =
    let
      val a = Word32.fromInt(a);
      val b = Word32.fromInt(b);
      fun Word32ToWord8Vector (item : Word32.word) =
        let
          (* index begins from 0 from less significant to
              the most significant bytes: [3 2 1 0] *)
          val numberOfBytes = 4;
          fun Word32ToWord8List ~1 = []
            | Word32ToWord8List (index) =
                let
                  val cuttedWord32Item = Word32.>> (Word32.<< (item,
                          Word.fromInt((numberOfBytes-1-index)*8)),
                          Word.fromInt((numberOfBytes-1)*8));
                  val SOME word8Item = Word8.fromString(Word32.toString
                          cuttedWord32Item);
                in
                  word8Item :: Word32ToWord8List (index - 1)
                end;

        in
          Word8Vector.fromList (Word32ToWord8List (numberOfBytes - 1))
        end;
      val dataVector = Word8Vector.concat ([Word32ToWord8Vector a, Word32ToWord8Vector b]);
    in
      Word8VectorSlice.slice (dataVector, 0, NONE)
    end;

  fun sendData (sock, a : int, b : int) =
    Socket.sendVec (sock, getData (a, b));

  fun recvData sock =
  let
    fun word8VectorToWord32 (word8VectorData) =
      Word8Vector.foldl (fn (item, result) => Word32.+ (Word32.<< (result, Word.fromInt(8)),
        Word32.fromInt (Word8.toInt item))) (Word32.fromInt 0) word8VectorData;
    val data = Socket.recvVec(sock, 4);
  in
    Word32.toInt (word8VectorToWord32 data)
  end;

in

  fun sendRequest (sock, a : int, b : int) =
  let
    val _ = sendData (sock, a, b);
  in
    recvData sock
  end;

end;

fun connectToServer(domain : string, port_number : int) =
let
  val sock = INetSock.TCP.socket();
  val sockAddr =
    let
      val SOME entry = NetHostDB.getByName domain;
    in
      INetSock.toAddr(NetHostDB.addr entry, port_number)
    end;
  val _ = Socket.connect (sock, sockAddr);
(*  val _ = Socket.Ctl.setKEEPALIVE (sock, true); *)

  val _ = sendRequest(sock, 0, 1);
in
  sock
end;

fun closeConnection sock =
let
  val _ = sendRequest (sock, 0, 0);
in
  Socket.close sock
end;
