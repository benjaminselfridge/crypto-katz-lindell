-- | A library of attacks against various encryption schemes found in
-- Katz/Lindell.

module Crypto.Attacks
  ( -- * Attacks
    bruteForce
  , bruteForceEnglish
  , breakSubstCipher
    -- * Handy distribution utilities
  , Distribution
  , getDistribution
  , englishDistribution
  , dotDistribution
  ) where

import Debug.Trace

import Crypto.Schemes
import Crypto.Types

import Data.List (nub, sortBy, sortOn, (\\))
import qualified Data.Map as Map
import Data.Maybe (fromJust)
import Math.Combinat.Permutations

-- | A brute-force attack can be applied on any encryption scheme. Given a
-- ciphertext to decrypt, the scheme @s@ it was encrypted with, and a list of
-- @key@s to try, simply apply @decrypt s key ciphertext@ for each @key@ in the
-- list, and give a list of all the results along with the @key@s used to
-- generate them.
bruteForce :: PrivateKeyScheme key plaintext ciphertext
           -> [key] -- ^ list of keys to try
           -> ciphertext
           -> [(key, plaintext)]
bruteForce s keys ciphertext = zip keys (flip (decrypt s) ciphertext <$> keys)

-- | @bruteForce@ where @plaintext ~ [Alpha]@, sorted by closeness to English's
-- letter distribution.
bruteForceEnglish :: PrivateKeyScheme key [Alpha] ciphertext
                  -> [key] -- ^ list of keys to try
                  -> ciphertext
                  -> [(key, [Alpha])]
bruteForceEnglish s keys ciphertext =
  let pairs = bruteForce s keys ciphertext
      eDot = englishDistribution `dotDistribution` englishDistribution
      o (k, p) (k', p') = abs ( eDot - getDistribution p  `dotDistribution` englishDistribution) `compare`
                          abs ( eDot - getDistribution p' `dotDistribution` englishDistribution)
  in sortBy o pairs

-- | Attempts to break a substitution cipher given the ciphertext. This only
-- gives a (usually prety bad) first guess based on English letter frequency.
breakSubstCipher :: [Alpha] -> (Permutation, [Alpha])
breakSubstCipher ciphertext =
  let dist = getDistribution ciphertext
      distLetters' = fst <$> reverse (sortOn snd (Map.toList dist))
      distLetters = distLetters' ++ ([A .. Z] \\ distLetters')
      engLetters'  = fst <$> reverse (sortOn snd (Map.toList englishDistribution))
      engLetters = engLetters' ++ ([A .. Z] \\ engLetters')
      pairs = zip engLetters distLetters
      sigma = toPermutation $
        map (\a -> 1 + fromEnum (fromJust (lookup a pairs))) [A .. Z]
  in (sigma, decrypt substCipher sigma ciphertext)

-- | A distribution of @a@s is a list of the probability of their occurrence in
-- a given piece of plaintext.
type Distribution a = Map.Map a Float

-- | Compute a 'Distribution' from an input list.
getDistribution :: Ord a => [a] -> Distribution a
getDistribution as =
  let counts = foldr (flip (Map.insertWith (+)) 1.0) Map.empty as
      totalCount = length as
  in fmap (/ fromIntegral totalCount) counts

-- | Computes @Sum p_i*q_i@, where @i@ indexes the @a@ type, and @p_i@, @q_i@
-- are the probabilities at @i@ of the two input distributions.
dotDistribution :: Ord a => Distribution a -> Distribution a -> Float
dotDistribution d1 d2 =
  let as = nub (Map.keys d1 ++ Map.keys d2)
  in sum $ map (\a -> Map.findWithDefault 0.0 a d1 * Map.findWithDefault 0.0 a d2) as

-- | Average letter frequencies for English-language text, as given in
-- Katz/Lindell page 13, Figure 1.2.
englishDistribution :: Distribution Alpha
englishDistribution = Map.fromList
  [ (A, 0.082)
  , (B, 0.015)
  , (C, 0.028)
  , (D, 0.042)
  , (E, 0.127)
  , (F, 0.022)
  , (G, 0.020)
  , (H, 0.061)
  , (I, 0.070)
  , (J, 0.001)
  , (K, 0.008)
  , (L, 0.040)
  , (M, 0.024)
  , (N, 0.067)
  , (O, 0.075)
  , (P, 0.019)
  , (Q, 0.001)
  , (R, 0.060)
  , (S, 0.063)
  , (T, 0.090)
  , (U, 0.028)
  , (V, 0.010)
  , (W, 0.024)
  , (X, 0.020)
  , (Y, 0.001)
  , (Z, 0.001)
  ]
