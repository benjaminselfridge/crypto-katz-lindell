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

-- type family Key (scheme :: Type) :: Type
-- type family Plaintext (scheme :: Type) :: Type
-- type family Ciphertext (scheme :: Type) :: Type

-- data PrivateKeyScheme scheme = PrivateKeyScheme
--   { generateKey :: forall m g . MonadRandom m => m (Key scheme)
--     -- | Encryption is allowed to be probabilistic.
--   , encrypt :: forall m g . MonadRandom m
--             => Key scheme
--             -> Plaintext scheme
--             -> m (Ciphertext scheme)
--     -- | Decryption is deterministic.
--   , decrypt :: Key scheme -> Ciphertext scheme -> Plaintext scheme
--   }

data PrivateKeyScheme key plaintext ciphertext = PrivateKeyScheme
  { generateKey :: forall m . MonadRandom m => m key
  , encrypt :: forall m . MonadRandom m => key -> plaintext -> m ciphertext
  , decrypt :: key -> ciphertext -> plaintext
  }

data Alpha = A | B | C | D | E | F | G | H
           | I | J | K | L | M | N | O | P
           | Q | R | S | T | U | V | W | X
           | Y | Z
  deriving (Show, Eq, Ord, Enum)

fromChar :: Char -> Alpha
fromChar 'A' = A
fromChar 'B' = B
fromChar 'C' = C
fromChar 'D' = D
fromChar 'E' = E
fromChar 'F' = F
fromChar 'G' = G
fromChar 'H' = H
fromChar 'I' = I
fromChar 'J' = J
fromChar 'K' = K
fromChar 'L' = L
fromChar 'M' = M
fromChar 'N' = N
fromChar 'O' = O
fromChar 'P' = P
fromChar 'Q' = Q
fromChar 'R' = R
fromChar 'S' = S
fromChar 'T' = T
fromChar 'U' = U
fromChar 'V' = V
fromChar 'W' = W
fromChar 'X' = X
fromChar 'Y' = Y
fromChar 'Z' = Z
fromChar c = error $ "fromChar \'" ++ [c] ++ "' :: Alpha not implemented"

toChar :: Alpha -> Char
toChar A = 'A'
toChar B = 'B'
toChar C = 'C'
toChar D = 'D'
toChar E = 'E'
toChar F = 'F'
toChar G = 'G'
toChar H = 'H'
toChar I = 'I'
toChar J = 'J'
toChar K = 'K'
toChar L = 'L'
toChar M = 'M'
toChar N = 'N'
toChar O = 'O'
toChar P = 'P'
toChar Q = 'Q'
toChar R = 'R'
toChar S = 'S'
toChar T = 'T'
toChar U = 'U'
toChar V = 'V'
toChar W = 'W'
toChar X = 'X'
toChar Y = 'Y'
toChar Z = 'Z'

newtype AlphaString = AlphaString { unAlphaString :: [Alpha] }

instance Show AlphaString where
  show = show . map toChar . unAlphaString

type instance Element AlphaString = Alpha

instance MonoFunctor AlphaString where
  omap f = AlphaString . map f . unAlphaString

instance MonoFoldable AlphaString where
  ofoldMap f = foldMap f . unAlphaString
  ofoldr f b = foldr f b . unAlphaString
  ofoldl' f b = foldl' f b . unAlphaString
  ofoldr1Ex f = foldr1 f . unAlphaString
  ofoldl1Ex' f = foldl1' f . unAlphaString

instance MonoTraversable AlphaString where
  otraverse f = fmap AlphaString . traverse f . unAlphaString

instance IsString AlphaString where
  fromString = AlphaString . map fromChar

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
