{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}

-- | Miscellaneous types used by various other modules in this library.

module Crypto.Types
  ( -- * Text types
    Alpha(..)
  , alphaFromChar
  , alphaToChar
  ) where

-- | Alphabetical character, for schemes that only use letters.
data Alpha = A | B | C | D | E | F | G | H
           | I | J | K | L | M | N | O | P
           | Q | R | S | T | U | V | W | X
           | Y | Z
  deriving (Show, Eq, Ord, Enum)

-- | Convert a 'Char' to an 'Alpha'. Throw error if the input is not one of the
-- 26 uppercase letters.
alphaFromChar :: Char -> Alpha
alphaFromChar 'A' = A
alphaFromChar 'B' = B
alphaFromChar 'C' = C
alphaFromChar 'D' = D
alphaFromChar 'E' = E
alphaFromChar 'F' = F
alphaFromChar 'G' = G
alphaFromChar 'H' = H
alphaFromChar 'I' = I
alphaFromChar 'J' = J
alphaFromChar 'K' = K
alphaFromChar 'L' = L
alphaFromChar 'M' = M
alphaFromChar 'N' = N
alphaFromChar 'O' = O
alphaFromChar 'P' = P
alphaFromChar 'Q' = Q
alphaFromChar 'R' = R
alphaFromChar 'S' = S
alphaFromChar 'T' = T
alphaFromChar 'U' = U
alphaFromChar 'V' = V
alphaFromChar 'W' = W
alphaFromChar 'X' = X
alphaFromChar 'Y' = Y
alphaFromChar 'Z' = Z
alphaFromChar c = error $ "alphaFromChar \'" ++ [c] ++ "' :: Alpha not implemented"

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
