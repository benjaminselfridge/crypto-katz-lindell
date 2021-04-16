{-# LANGUAGE RankNTypes #-}

-- | A library of attacks against various encryption schemes found in
-- Katz/Lindell.
module Crypto.Attacks
  ( -- * Types of attacks
    CiphertextOnlyAttack
  , KnownPlaintextAttack
  , ChosenPlaintextAttack
  , ChosenCiphertextAttack
    -- * General attacks
  , bruteForce
  , bruteForceWithDist
  , bruteForceEnglish
    -- * Scheme-specific attacks
  , breakShiftCipher
  , breakShiftCipherEnglish
  , breakShiftCipherKnownPlaintext
  , breakSubstCipher
    -- * Handy distribution utilities
  , Distribution
  , getDistribution
  , englishDistribution
  , dotDistribution
  ) where

import Crypto.Schemes
import Crypto.Types

import Control.Monad.Random
import Data.List (nub, sortBy, sortOn, (\\))
import qualified Data.Map as Map
import Data.Maybe (fromJust)
import Data.Ord (Down(..))
import Math.Combinat.Permutations

-- | A ciphertext-only attack is an attack that only needs the ciphertext to
-- produce a result. (Katz/Lindell pg. 8)
type CiphertextOnlyAttack key plaintext ciphertext = ciphertext -> [(key, plaintext)]

-- | A known-plaintext attack takes a list of plaintext/ciphertext pairs which
-- were all encrypted with the same key, and uses it to decrypt some other
-- ciphertext encrypted by that key. (Katz/Lindell pg. 8)
type KnownPlaintextAttack key plaintext ciphertext =
  [(plaintext, ciphertext)] -> CiphertextOnlyAttack key plaintext ciphertext

-- | A chosen-plaintext attack is an attack where the encryption function can be
-- called arbitrarily, and the key remains fixed. (Katz/Lindell pg. 8)
type ChosenPlaintextAttack key plaintext ciphertext =
  EncryptFn plaintext ciphertext -> CiphertextOnlyAttack key plaintext ciphertext

-- | A chosen-ciphertext attack is an attack where the decryption function can
-- be called arbitrarily, and the key remains fixed. (Katz/Lindell pg. 8)
type ChosenCiphertextAttack key plaintext ciphertext =
  DecryptFn plaintext ciphertext -> CiphertextOnlyAttack key plaintext ciphertext

-- | A brute-force attack can be applied on any encryption scheme. Given a
-- ciphertext to decrypt, the scheme @s@ it was encrypted with, and a list of
-- @key@s to try, simply apply @decrypt s key ciphertext@ for each @key@ in the
-- list, and give a list of all the results along with the @key@s used to
-- generate them.
bruteForce :: [key] -- ^ list of keys to try
           -> PrivateKeyScheme key plaintext ciphertext
           -> CiphertextOnlyAttack key plaintext ciphertext
bruteForce keys s ciphertext = zip keys (flip (decrypt s) ciphertext <$> keys)

-- | A brute-force attack where @plaintext ~ [a]@ for some @Ord a => a@, sorted
-- by closeness to a given letter distribution.
bruteForceWithDist :: Ord a
                   => Distribution a -- ^ reference distribution
                   -> [key] -- ^ list of keys to try
                   -> PrivateKeyScheme key [a] ciphertext
                   -> CiphertextOnlyAttack key [a] ciphertext
bruteForceWithDist refDist s keys ciphertext =
  let pairs = bruteForce s keys ciphertext
      rDot = refDist `dotDistribution` refDist
      o (k, p) (k', p') = abs ( rDot - getDistribution p  `dotDistribution` refDist) `compare`
                          abs ( rDot - getDistribution p' `dotDistribution` refDist)
  in sortBy o pairs

-- | A brute-force attack where @plaintext ~ [Alpha]@, sorted by closeness to
-- English's letter distribution.
bruteForceEnglish :: [key] -- ^ list of keys to try
                  -> PrivateKeyScheme key [Alpha] ciphertext
                  -> CiphertextOnlyAttack key [Alpha] ciphertext
bruteForceEnglish = bruteForceWithDist englishDistribution

-- | Brute-force, ciphertext-only attack on 'shiftCipher'.
breakShiftCipher :: CiphertextOnlyAttack Int [Alpha] [Alpha]
breakShiftCipher = bruteForce [0..25] shiftCipher

-- | Brute-force, English-biased ciphertext-only attack on 'shiftCipher'.
breakShiftCipherEnglish :: CiphertextOnlyAttack Int [Alpha] [Alpha]
breakShiftCipherEnglish = bruteForceEnglish [0..25] shiftCipher

-- | Known-plaintext attack on 'shiftCipher'. Assumes the input pairs are valid;
-- does not check for this. If the input list contains only pairs of empty
-- strings, this degenerates into a brute-force attack. Assuming any of the
-- input pairs contain nonempty strings, this is guaranteed to be correct for
-- any shift cipher, and only produces one result.
breakShiftCipherKnownPlaintext :: KnownPlaintextAttack Int [Alpha] [Alpha]
breakShiftCipherKnownPlaintext [] ciphertext = breakShiftCipher ciphertext
breakShiftCipherKnownPlaintext (([],_):pairs) ciphertext =
  breakShiftCipherKnownPlaintext pairs ciphertext
-- NB: The below case only happens if the input was invalid.
breakShiftCipherKnownPlaintext ((_,[]):pairs) ciphertext =
  breakShiftCipherKnownPlaintext pairs ciphertext
breakShiftCipherKnownPlaintext ((p:ps,c:cs):_) ciphertext =
  let key = (fromEnum c - fromEnum p) `mod` 26
  in [(key, decrypt shiftCipher key ciphertext)]

-- | Attempts to break a substitution cipher given an expected distribution of
-- alphabetical characters.
breakSubstCipher :: Distribution Alpha -> CiphertextOnlyAttack Permutation [Alpha] [Alpha]
breakSubstCipher refDist ciphertext =
  let dist = getDistribution ciphertext
      distLetters' = fst <$> sortOn (Down . snd) (Map.toList dist)
      distLetters = distLetters' ++ ([A .. Z] \\ distLetters')
      refLetters'  = fst <$> sortOn (Down . snd) (Map.toList refDist)
      refLetters = refLetters' ++ ([A .. Z] \\ refLetters')
      pairs = zip refLetters distLetters
      sigma = toPermutation $
        map (\a -> 1 + fromEnum (fromJust (lookup a pairs))) [A .. Z]
  in [(sigma, decrypt substCipher sigma ciphertext)]

-- | A distribution of @a@s is a list of the probability of their occurrence in
-- a given piece of plaintext.
type Distribution a = Map.Map a Float

-- | Compute a 'Distribution' from an input list.
getDistribution :: Ord a => [a] -> Distribution a
getDistribution as =
  let counts = foldr (flip (Map.insertWith (+)) 1.0) Map.empty as
      totalCount = length as
  in fmap (/ fromIntegral totalCount) counts

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

-- | Computes @Sum p_i*q_i@, where @i@ indexes the @a@ type, and @p_i@, @q_i@
-- are the probabilities at @i@ of the two input distributions.
dotDistribution :: Ord a => Distribution a -> Distribution a -> Float
dotDistribution d1 d2 =
  let as = nub (Map.keys d1 ++ Map.keys d2)
  in sum $ map (\a -> Map.findWithDefault 0.0 a d1 * Map.findWithDefault 0.0 a d2) as
