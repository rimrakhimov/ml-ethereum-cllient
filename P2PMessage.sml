use "rlp";

datatype capability = Capability of string*Word32.word;

datatype handshake = Handshake of
     Word64.word * string * capability list * Word64.word * Word64.word;

datatype p2pmessage = Hello of handshake | Disconnet;

exception WrongMessageFormat of string;

fun encodeHandshake (
  Handshake(protocolVersion,
            clientId,
            capabilities,
            listenPort,
            nodeId)) =
  let
    val encodedProtocolVersion = Rlp.Encoder.encodeWord64 protocolVersion

    val encodedClientId = Rlp.Encoder.encodeString clientId

    fun encodeCapabilities capabilities =
      let
        fun encodeCapabilitiesItems ([], currentResult) = List.rev currentResult
          | encodeCapabilitiesItems ((Capability(cap, capVersion)) :: ls, currentResult) =
              let
                val encodedCap = Rlp.Encoder.encodeString cap
                val encodedCapVersion = Rlp.Encoder.encodeWord32 capVersion
                val encodedCapability = Rlp.Encoder.encodeRlpResultsList [encodedCap, encodedCapVersion]
              in
               encodeCapabilitiesItems(ls, encodedCapability :: currentResult)
              end
      in
        Rlp.Encoder.encodeRlpResultsList (encodeCapabilitiesItems (capabilities, []))
      end
    val encodedCapabilities = encodeCapabilities capabilities

    val encodedListenPort = Rlp.Encoder.encodeWord64 listenPort

    val encodedNodeId = Rlp.Encoder.encodeWord64 nodeId
  in
    Rlp.Encoder.encodeRlpResultsList [
      encodedProtocolVersion,
      encodedClientId,
      encodedCapabilities,
      encodedListenPort,
      encodedNodeId
    ]
  end;

fun decodeHandshake (message : Word8Vector.vector) =
  let
    val messageSize = Word8Vector.length message
    val wrappedMessage = Rlp.Decoder.formRlpResult message
    val wrappedMessageOffset = Word8.toInt (Rlp.getRlpResultOffset wrappedMessage)
    val wrappedMessageLen = Word64.toInt (Rlp.getRlpResultLength wrappedMessage)
    val _ =
      if wrappedMessageOffset + wrappedMessageLen <> messageSize
        then raise WrongMessageFormat "The message is not single Rlp encoded list"
        else ()

    val encodedList = Rlp.Decoder.decodeRlpList wrappedMessage
    val encodedListVector = Vector.fromList encodedList
    val _ =
      if Vector.length encodedListVector < 5
        then raise WrongMessageFormat "Hello message must have at least 5 elements"
        else ()

    val encodedProtocolVersion = Vector.sub (encodedListVector, 0)
    val protocolVersion = Rlp.Decoder.decodeWord64 encodedProtocolVersion

    val encodedClientId = Vector.sub (encodedListVector, 1)
    val clientId = Rlp.Decoder.decodeString encodedClientId

    (* TODO: decoding of capabilities *)

    val encodedListenPort = Vector.sub (encodedListVector, 3)
    val listenPort = Rlp.Decoder.decodeWord64 encodedListenPort

    val encodedNodeId = Vector.sub (encodedListVector, 4)
    val nodeId = Rlp.Decoder.decodeWord64 encodedNodeId
  in
    Handshake (protocolVersion, clientId, [], listenPort, nodeId)
  end




