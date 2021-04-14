{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto where

import Control.Arrow (first)
import Control.Monad.Random
import qualified Data.BitVector.Sized as BV
import Data.Foldable (foldl')
import Data.Kind
import Data.List (foldl1')
import Data.Maybe (fromJust)
import Data.MonoTraversable
import Data.String
import GHC.List (errorEmptyList)
import GHC.TypeNats
import Math.Combinat.Permutations

shiftEnum :: Enum a => Int -> a -> a
shiftEnum i = toEnum . (`mod` 26) . (+i) . fromEnum

shiftCipher :: PrivateKeyScheme Int AlphaString AlphaString
shiftCipher = PrivateKeyScheme
  { generateKey = (`mod` 26) <$> getRandom
  , encrypt = \key -> return . omap (shiftEnum key)
  , decrypt = \key -> omap (shiftEnum (-key))
  }

-- data SubstCipher

-- type instance Key        SubstCipher = Permutation
-- type instance Plaintext  SubstCipher = AlphaString
-- type instance Ciphertext SubstCipher = AlphaString

-- substCipher :: PrivateKeyScheme SubstCipher
-- substCipher = PrivateKeyScheme
--   { generateKey = (fst . randomPermutation 26 . mkStdGen) <$> getRandom
--   , encrypt = \k -> return . omap (fromJust . flip lookup (zip [A .. Z] (permuteList k [A .. Z])))
--   , decrypt = \k -> omap (fromJust . flip lookup (zip (permuteList k [A .. Z]) [A .. Z]))
--   }

-- bruteForce :: Enum (Key scheme)
--            => PrivateKeyScheme scheme
--            -> Key scheme -- ^ min key
--            -> Key scheme -- ^ max key
--            -> Ciphertext scheme
--            -> [Plaintext scheme]
-- bruteForce scheme minB maxB cipherText =
--   flip (decrypt scheme) cipherText <$> [minB .. maxB]

-- data OneTimePad (w :: Nat)

-- type instance Key        (OneTimePad w) = BV.BV w
-- type instance Plaintext  (OneTimePad w) = BV.BV w
-- type instance Ciphertext (OneTimePad w) = BV.BV w

-- oneTimePad :: BV.NatRepr w -> PrivateKeyScheme (OneTimePad w)
-- oneTimePad w = PrivateKeyScheme
--   { generateKey = BV.mkBV w <$> getRandom
--   , encrypt = \k -> return . BV.xor k
--   , decrypt = BV.xor
--   }
