-- | A library of encryption schemes found in Katz/Lindell.

module Crypto.Schemes
  ( -- * Private key schemes
    shiftCipher
  , substCipher
  , oneTimePad
  ) where

import Crypto.Types

import Control.Monad.Random
import qualified Data.BitVector.Sized as BV
import Data.Maybe (fromJust)
import Data.MonoTraversable
import Math.Combinat.Permutations

shiftEnum :: Enum a => Int -> a -> a
shiftEnum i = toEnum . (`mod` 26) . (+i) . fromEnum

-- | Shift cipher. The key is an 'Int' between 0 and 25 (inclusive), and we
-- shift each character by that amount to encrypt.
shiftCipher :: PrivateKeyScheme Int AlphaString AlphaString
shiftCipher = PrivateKeyScheme
  { generateKey = (`mod` 26) <$> getRandom
  , encrypt = \key -> return . omap (shiftEnum key)
  , decrypt = \key -> omap (shiftEnum (-key))
  }

-- | Substitution cipher. They key is a 'Permutation' on the alphabet, and we
-- simply apply the permutation to encrypt.
substCipher :: PrivateKeyScheme Permutation AlphaString AlphaString
substCipher = PrivateKeyScheme
  { generateKey = (fst . randomPermutation 26 . mkStdGen) <$> getRandom
  , encrypt = \k -> return . omap (fromJust . flip lookup (zip [A .. Z] (permuteList k [A .. Z])))
  , decrypt = \k -> omap (fromJust . flip lookup (zip (permuteList k [A .. Z]) [A .. Z]))
  }

-- | One-time pad on bitvectors of a given length.
oneTimePad :: BV.NatRepr w -> PrivateKeyScheme (BV.BV w) (BV.BV w) (BV.BV w)
oneTimePad w = PrivateKeyScheme
  { generateKey = BV.mkBV w <$> getRandom
  , encrypt = \k -> return . BV.xor k
  , decrypt = BV.xor
  }
