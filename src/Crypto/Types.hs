{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.Types
  ( -- * Private key encryption schemes
    PrivateKeyScheme(..)
    -- * Text types
  , Alpha(..)
  ) where

import Control.Monad.Random
import Data.Foldable (foldl')
import Data.List (foldl1')
import Data.MonoTraversable
import Data.String

-- | Private key scheme, as defined in Katz/Lindell page 4.
--
-- Note that, given a scheme @s@, and for all keys @k@ and messages @p@, we must
-- have
--
-- @
--   decrypt s k (encrypt s k m) == m
-- @
data PrivateKeyScheme key plaintext ciphertext = PrivateKeyScheme
  { generateKey :: forall m . MonadRandom m => m key
    -- ^ Generate a random key.
  , encrypt :: forall m . MonadRandom m => key -> plaintext -> m ciphertext
    -- ^ Encrypt plaintext with a given key. Note that encryption can be
    -- probabilistic (but doesn't have to be).
  , decrypt :: key -> ciphertext -> plaintext
    -- ^ Decrypt plaintext with a given key. Decryption is deterministic.
  }

-- | Alphabetical character, for schemes that only use letters.
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

-- | String of alphabetical characters only. Note that the 'IsString' instance
-- throws an error if you supply anything besides a string of uppercase letters.
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
