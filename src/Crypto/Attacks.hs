module Crypto.Attacks
  ( bruteForce
  ) where

import Crypto.Types

bruteForce :: Enum key
           => PrivateKeyScheme key plaintext ciphertext
           -> key -- ^ min key
           -> key -- ^ max key
           -> ciphertext
           -> [plaintext]
bruteForce s minB maxB ciphertext =
  flip (decrypt s) ciphertext <$> [minB .. maxB]
