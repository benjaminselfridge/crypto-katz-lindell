-- | A library of attacks against various encryption schemes found in
-- Katz/Lindell.

module Crypto.Attacks
  ( bruteForce
  ) where

import Crypto.Schemes

-- | A brute-force attack can be applied on any encryption scheme for which we
-- can enumerate keys. Given a ciphertext to decrypt, the scheme @s@ it was
-- encrypted with, and a range of @key@s, simply apply @decrypt s key
-- ciphertext@ for each @key@ in the range, and give a list of all the results
-- along with the @key@s used to generate them.
bruteForce :: Enum key
           => PrivateKeyScheme key plaintext ciphertext
           -> key -- ^ min key
           -> key -- ^ max key
           -> ciphertext
           -> [(key, plaintext)]
bruteForce s minB maxB ciphertext =
  withArg (flip (decrypt s) ciphertext) <$> [minB .. maxB]
  where withArg :: (a -> b) -> a -> (a, b)
        withArg f a = (a, f a)
