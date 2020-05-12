use "libs/random/random.sig";

use "libs/crypto/drbg/drbg";
use "libs/crypto/drbg/hmac_drbg";
use "libs/crypto/hmac";
use "libs/crypto/hash/keccak256";
use "utils";



local
  structure Rand = Drbg(HmacDrbg(Hmac(Keccak256)))
in
structure HmacDrbgRandom : RANDOM =
struct
  val rand = Rand.instantiate(NONE)

  fun generateVector (len, reseed : bool) = Rand.generate (rand, len, reseed, NONE)

  fun generateWord8 (reseed : bool) = Utils.word8VectorToWord8 (
    Rand.generate (rand, 1, reseed, NONE)
  )

  fun generateWord16 (reseed : bool) = Utils.word8VectorToWord16 (
    Rand.generate (rand, 2, reseed, NONE)
  )

   fun generateWord32 (reseed : bool) = Utils.word8VectorToWord32 (
    Rand.generate (rand, 4, reseed, NONE)
  )

  fun generateWord64 (reseed : bool) = Utils.word8VectorToWord64 (
    Rand.generate (rand, 8, reseed, NONE)
  )

end
end
