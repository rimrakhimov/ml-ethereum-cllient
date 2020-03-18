fun println s =
    (print (s ^ "\n"); TextIO.flushOut TextIO.stdOut);

fun word8VectorToWord32 (word8VectorData) =
  Word32.fromLargeWord (PackWord32Big.subVec (word8VectorData, 0));

fun word32ToWord8Vector (item : Word32.word) =
  let
    val arr = Word8Array.array(PackWord32Big.bytesPerElem, 0w0);
  in
    PackWord32Big.update (arr, 0, Word32.toLargeWord item);
    Word8Array.vector arr
  end;

fun closeConnection conn =
    let
      val _ = ()
    in
      Socket.close conn;
      Thread.Thread.exit;
      ()
    end;

fun recv conn maxNumberOfBytes =
  let
    val data = Socket.recvVec (conn, maxNumberOfBytes);
    val recvNumberOfBytes = Word8Vector.length data;
  in
    if recvNumberOfBytes = 0
      then (println "Connection broken"; closeConnection conn; Word8Vector.fromList [] )
    else if recvNumberOfBytes < maxNumberOfBytes
      then Word8Vector.concat [data, (recv conn (maxNumberOfBytes -
                                    recvNumberOfBytes))]
    else data
  end;

fun recvWord32 conn =
  word8VectorToWord32 (recv conn 4);

fun sendWord32 conn w =
  let
    val data = word32ToWord8Vector w;
    val len = Word8Vector.length data;
    val toSend = Word8VectorSlice.slice (data, 0, SOME len)
  in
    Socket.sendVec (conn, toSend)
  end;

fun handleConn conn handler =
  let
    val a = recvWord32 conn;
    val b = recvWord32 conn;
    val resp = handler (a, b);
  in
    if a = (Word32.fromInt 0) andalso b = (Word32.fromInt 0)
      then (println "Connection closed"; closeConnection conn; ())
    else (println "I'm here"; sendWord32 conn resp; handleConn conn handler)
  end;


fun serverForever masterSock handler =
  let
    val _ = println "Waiting for connection ...";
    fun fork conn =
      Thread.Thread.fork (fn () => handleConn conn handler, []);
    val (conn, _) = Socket.accept masterSock;
  in
    fork conn;
    serverForever masterSock handler;
    ()
  end;


fun listenAndServe port handler =
  let
    val masterSock = INetSock.TCP.socket();
    val sleep = OS.Process.sleep;
    fun bind () =
      let
        fun doBind() = Socket.bind (masterSock, INetSock.any port)
      in
        doBind() handle SysError => (sleep (Time.fromSeconds 1); bind());
        ()
      end;
  in
    println "Binding server...";
    bind();
    println ("Server bound... Listening on port " ^ (Int.toString port));
    Socket.listen (masterSock, 1024);
    Socket.Ctl.setREUSEADDR(masterSock, true);

    serverForever masterSock handler

  end;
