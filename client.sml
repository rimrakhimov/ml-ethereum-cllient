fun word8VectorToWord32 (word8VectorData) =
  Word32.fromLargeWord (PackWord32Big.subVec (word8VectorData, 0));

fun word32ToWord8Vector (item : Word32.word) =
  let
    val arr = Word8Array.array(PackWord32Big.bytesPerElem, 0w0);
  in
    PackWord32Big.update (arr, 0, Word32.toLargeWord item);
    Word8Array.vector arr
  end;

local
  fun getData (a : int, b : int) =
    let
      val a = Word32.fromInt(a);
      val b = Word32.fromInt(b);
      val dataVector = Word8Vector.concat ([word32ToWord8Vector a, word32ToWord8Vector b]);
    in
      Word8VectorSlice.slice (dataVector, 0, NONE)
    end;

  fun sendData (sock, a : int, b : int) =
    Socket.sendVec (sock, getData (a, b));

  fun recvData sock =
  let
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
