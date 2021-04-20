{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}

-- | Miscellaneous types used by various other modules in this library.

module Crypto.Types
  ( -- * Text types
    Alpha(..)
  , alphaFromChar
  , alphasFromString
  , alphaToChar
  , shiftAlpha
  , permuteAlpha
  ) where

import Data.Array.IArray ((!))
import Data.Char (toUpper)
import Data.Maybe (mapMaybe)
import Math.Combinat.Permutations
import Test.QuickCheck

-- | Alphabetical character, for schemes that only use letters.
data Alpha = A | B | C | D | E | F | G | H
           | I | J | K | L | M | N | O | P
           | Q | R | S | T | U | V | W | X
           | Y | Z
  deriving (Show, Eq, Ord, Enum)

instance Arbitrary Alpha where
  arbitrary = chooseEnum (A, Z)

-- | Convert a 'Char' to an 'Alpha'. Throw error if the input is not one of the
-- 26 uppercase letters.
alphaFromChar :: Char -> Maybe Alpha
alphaFromChar 'A' = Just A
alphaFromChar 'B' = Just B
alphaFromChar 'C' = Just C
alphaFromChar 'D' = Just D
alphaFromChar 'E' = Just E
alphaFromChar 'F' = Just F
alphaFromChar 'G' = Just G
alphaFromChar 'H' = Just H
alphaFromChar 'I' = Just I
alphaFromChar 'J' = Just J
alphaFromChar 'K' = Just K
alphaFromChar 'L' = Just L
alphaFromChar 'M' = Just M
alphaFromChar 'N' = Just N
alphaFromChar 'O' = Just O
alphaFromChar 'P' = Just P
alphaFromChar 'Q' = Just Q
alphaFromChar 'R' = Just R
alphaFromChar 'S' = Just S
alphaFromChar 'T' = Just T
alphaFromChar 'U' = Just U
alphaFromChar 'V' = Just V
alphaFromChar 'W' = Just W
alphaFromChar 'X' = Just X
alphaFromChar 'Y' = Just Y
alphaFromChar 'Z' = Just Z
alphaFromChar _ = Nothing

-- | Convert an 'Alpha' to a 'Char'.
alphaToChar :: Alpha -> Char
alphaToChar A = 'A'
alphaToChar B = 'B'
alphaToChar C = 'C'
alphaToChar D = 'D'
alphaToChar E = 'E'
alphaToChar F = 'F'
alphaToChar G = 'G'
alphaToChar H = 'H'
alphaToChar I = 'I'
alphaToChar J = 'J'
alphaToChar K = 'K'
alphaToChar L = 'L'
alphaToChar M = 'M'
alphaToChar N = 'N'
alphaToChar O = 'O'
alphaToChar P = 'P'
alphaToChar Q = 'Q'
alphaToChar R = 'R'
alphaToChar S = 'S'
alphaToChar T = 'T'
alphaToChar U = 'U'
alphaToChar V = 'V'
alphaToChar W = 'W'
alphaToChar X = 'X'
alphaToChar Y = 'Y'
alphaToChar Z = 'Z'

-- | Converts a string to a list of 'Alpha's by mapping the characters to
-- uppercase and removing characters that are not alphabetical.
alphasFromString :: String -> [Alpha]
alphasFromString = mapMaybe (alphaFromChar . toUpper)

-- | Shift an 'Alpha' by a given amount. The input 'Int' does not have to be
-- between @0@ and @25@.
shiftAlpha :: Int -> Alpha -> Alpha
shiftAlpha i = toEnum . (`mod` 26) . (+i) . fromEnum

-- | Apply a permutation to an 'Alpha'. Assumes the input permutation is a
-- permutation on @[0..25]@.
permuteAlpha :: Permutation -> Alpha -> Alpha
permuteAlpha sigma a = fromPermIx (permutationUArray sigma ! toPermIx a)
  where toPermIx = (+ 1) . fromEnum
        fromPermIx = toEnum . subtract 1
