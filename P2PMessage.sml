use "rlp";

datatype capability = Capability of string*Word32.word;

datatype handshake = Handshake of
     Word64.word * string * capability list * Word64.word * Word64.word;

datatype p2pmessage = Hello of handshake | Disconnet

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
                val encodedCapVersion = Rlp.Encoder.encodeWord32 capVersion;
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
  end

