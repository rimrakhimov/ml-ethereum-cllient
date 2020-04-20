use "rlp";

signature P2P_MESSAGE =
sig
  structure RlpCoder : RLP

  type capability
  type handshake

  type disconnectReason
  type disconnect

  type p2pMessage

  val messageIdentifierValue : p2pMessage -> Word64.word
  val messageIdentifierName : p2pMessage -> string

  exception MessageFormat of string

  val encodeHandshake : handshake -> Word8Vector.vector
  val decodeHandshake : Word8Vector.vector -> handshake

  val encodeDisconnect : disconnect -> Word8Vector.vector
  val decodeDisconnect : Word8Vector.vector -> disconnect

  val encodeMessage : p2pMessage -> Word8Vector.vector
  val decodeMessage : Word8Vector -> p2pMessage

end

structure P2PMessage : P2P_MESSAGE =
struct
  structure RlpCoder = Rlp

  datatype capability = Capability of string * Word32.word

  datatype handshake = Handshake of
       Word64.word * string * capability list * Word64.word * Word64.word

  type disconnectReason = Word64.word
  datatype disconnect = Disconnect of disconnectReason option

  datatype p2pMessage = MessageHello of handshake       |
                        MessageDisconnect of disconnect |
                        MessagePing                     |
                        MessagePong

  fun messageIdentifierValue (message) : Word64.word =
    case message of
         MessageHello(_) => 0wx0      |
         MessageDisconnect(_) => 0wx1 |
         MessagePing => 0wx2       |
         MessagePong => 0wx3;

  fun messageIdentifierName (message) =
  let
    val names = Vector.fromList ["Hello", "Disconnect", "Ping", "Pong"]
    val index = Word64.toInt (messageIdentifierValue message)
  in
    Vector.sub (names, index)
  end;

  fun isDisconnectReasonValid (reason : Word64.word) =
    (reason < 0wx0c) orelse (reason = 0wx10)

  fun disconnectReasonDescription (reason) =
  let
    val disconnectReasonNames = Vector.fromList [
                                  "Requested",
                                  "TCP Error",
                                  "Breach Proto",
                                  "Useless Peer",
                                  "Too Many Peers",
                                  "Already Connected",
                                  "Incompatible P2P",
                                  "Null Node",
                                  "Client Quit",
                                  "Unexpected ID",
                                  "ID Same",
                                  "Timeout",
                                  "", (* 0x0c *)
                                  "", (* 0x0d *)
                                  "", (* 0x0e *)
                                  "", (* 0x0f *)
                                  "Protocol specific"
                                ]
  in
    if
      isDisconnectReasonValid reason
    then
      Vector.sub (disconnectReasonNames, Word64.toInt reason)
    else  (* reason is not valid *)
      ""
  end

  exception MessageFormat of string;

  fun encodeHandshake (
    Handshake(protocolVersion,
              clientId,
              capabilities,
              listenPort,
              nodeId)) =
  let
    val encodedProtocolVersion = RlpCoder.Encoder.encodeWord64 protocolVersion

    val encodedClientId = RlpCoder.Encoder.encodeString clientId

    fun encodeCapabilities capabilities =
      let
        fun encodeCapabilitiesItems ([], currentResult) = List.rev currentResult
          | encodeCapabilitiesItems ((Capability(cap, capVersion)) :: ls, currentResult) =
            let
              val encodedCap = RlpCoder.Encoder.encodeString cap
              val encodedCapVersion = RlpCoder.Encoder.encodeWord32 capVersion
              val encodedCapability = RlpCoder.Encoder.encodeRlpResultsList [encodedCap, encodedCapVersion]
            in
             encodeCapabilitiesItems(ls, encodedCapability :: currentResult)
            end
      in
        RlpCoder.Encoder.encodeRlpResultsList (encodeCapabilitiesItems (capabilities, []))
      end
    val encodedCapabilities = encodeCapabilities capabilities

    val encodedListenPort = RlpCoder.Encoder.encodeWord64 listenPort

    val encodedNodeId = RlpCoder.Encoder.encodeWord64 nodeId
  in
    Rlp.getRlpResultData (
      RlpCoder.Encoder.encodeRlpResultsList [
        encodedProtocolVersion,
        encodedClientId,
        encodedCapabilities,
        encodedListenPort,
        encodedNodeId
      ])
  end;

  fun decodeHandshake (message : Word8Vector.vector) =
  let
    val messageSize = Word8Vector.length message
    val wrappedMessage = RlpCoder.Decoder.formRlpResult message
    val wrappedMessageOffset = Word8.toInt (Rlp.getRlpResultOffset wrappedMessage)
    val wrappedMessageLen = Word64.toInt (Rlp.getRlpResultLength wrappedMessage)
    val _ =
      if wrappedMessageOffset + wrappedMessageLen <> messageSize
        then raise MessageFormat "The message is not single Rlp encoded list"
        else ()

    val encodedList = RlpCoder.Decoder.decodeList wrappedMessage
    val encodedListVector = Vector.fromList encodedList
    val _ =
      if Vector.length encodedListVector < 5
        then raise MessageFormat "Hello message must have at least 5 elements"
        else ()

    val encodedProtocolVersion = Vector.sub (encodedListVector, 0)
    val protocolVersion = RlpCoder.Decoder.decodeWord64 encodedProtocolVersion

    val encodedClientId = Vector.sub (encodedListVector, 1)
    val clientId = RlpCoder.Decoder.decodeString encodedClientId

    val encodedCapabilitiesList = Vector.sub (encodedListVector, 2)
    fun decodeCapabilitiesList [] = []
      | decodeCapabilitiesList (encodedCapability :: encodedCapabilities) =
        let
          val decodedCapability = RlpCoder.Decoder.decodeList encodedCapability
        in
          if
            List.length decodedCapability <> 2
          then
            raise MessageFormat "Capability must have two elements"
          else
            let
              val cap = RlpCoder.Decoder.decodeString (List.hd decodedCapability)
              val capVersion = RlpCoder.Decoder.decodeWord32 (List.last decodedCapability)
            in
              Capability(cap, capVersion) :: (decodeCapabilitiesList encodedCapabilities)
            end
        end
    val capabilities = decodeCapabilitiesList (RlpCoder.Decoder.decodeList encodedCapabilitiesList)

    val encodedListenPort = Vector.sub (encodedListVector, 3)
    val listenPort = RlpCoder.Decoder.decodeWord64 encodedListenPort

    val encodedNodeId = Vector.sub (encodedListVector, 4)
    val nodeId = RlpCoder.Decoder.decodeWord64 encodedNodeId
  in
    Handshake (protocolVersion, clientId, capabilities, listenPort, nodeId)
  end;

  fun encodeDisconnect (Disconnect NONE) =
        RlpCoder.getRlpResultData (RlpCoder.Encoder.encodeRlpResultsList [])
    | encodeDisconnect (Disconnect (SOME reason)) =
      let
        val encodedReason = RlpCoder.Encoder.encodeWord64 (reason)
      in
        RlpCoder.getRlpResultData (RlpCoder.Encoder.encodeRlpResultsList [encodedReason])
      end

  fun decodeDisconnect (message) =
  let
    val messageSize = Word8Vector.length message
    val wrappedMessage = RlpCoder.Decoder.formRlpResult message
    val wrappedMessageOffset = Word8.toInt (Rlp.getRlpResultOffset wrappedMessage)
    val wrappedMessageLen = Word64.toInt (Rlp.getRlpResultLength wrappedMessage)
    val _ =
      if wrappedMessageOffset + wrappedMessageLen <> messageSize
        then raise MessageFormat "The message is not single Rlp encoded list"
        else ()

    val encodedList = RlpCoder.Decoder.decodeList wrappedMessage
    val encodedListLen = List.length encodedList
    val _ =
      if encodedListLen > 1
        then raise MessageFormat "Disconnect message must have at most element"
        else ()
  in
    if
      encodedListLen = 0
    then
      Disconnect (NONE)
    else
      let
        val encodedReason = List.hd encodedList
        val reason = RlpCoder.Decoder.decodeWord64 encodedReason
      in
        if
          isDisconnectReasonValid reason
        then
          Disconnect (SOME reason)
        else
          Disconnect (NONE)
      end
  end

  fun encodeMessage (message : p2pMessage ) =
  let
    val messageBody =
      case message of
         MessageHello (hand) => encodeHandshake hand
       | MessageDisconnect (dis) => encodeDisconnect dis
       | MessagePing => RlpCoder.getRlpResultData RlpCoder.Encoder.encodedEmptyList
       | MessagePong => RlpCoder.getRlpResultData RlpCoder.Encoder.encodedEmptyList

    val messageId = RlpCoder.getRlpResultData (
      RlpCoder.Encoder.encodeWord64 (messageIdentifierValue message)
    )
  in
     (* TODO: add snappy compression for non Hello messages *)
    Word8Vector.concat [messageId, messageBody]
  end

end
