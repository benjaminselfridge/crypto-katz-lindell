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
  , guessPolyAlphaKeyLength
  , breakPoly
    -- * Scheme-specific attacks
  , breakMonoAlphaShift
  , breakMonoAlphaShiftEnglish
  , breakMonoAlphaShiftKnownPlaintext
  , breakPolyAlphaShiftEnglish
  , breakMonoAlphaSubst
  ) where

import Crypto.Schemes
import Crypto.Types
import Crypto.Utils

import Control.Monad.Random
import Data.Bifunctor (second)
import Data.List (nub, sortBy, sortOn, (\\), minimumBy, transpose)
import qualified Data.List.NonEmpty as LN
import qualified Data.Map as Map
import Data.Maybe (fromJust)
import Data.Ord (Down(..), comparing)
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

-- | A brute-force attack where @plaintext ~ [plainchar]@ for some @Ord
-- plainchar => plainchar@, sorted by closeness to a given letter distribution.
bruteForceWithDist :: Ord plainchar
                   => Distribution plainchar -- ^ reference distribution
                   -> [key] -- ^ list of keys to try
                   -> PrivateKeyScheme key [plainchar] ciphertext
                   -> CiphertextOnlyAttack key [plainchar] ciphertext
bruteForceWithDist refDist s keys ciphertext =
  let pairs = bruteForce s keys ciphertext
  in sortBy (comparing (d' refDist . getDist . snd)) pairs

-- | A brute-force attack where @plaintext ~ [Alpha]@, sorted by closeness to
-- English's letter distribution.
bruteForceEnglish :: [key] -- ^ list of keys to try
                  -> PrivateKeyScheme key [Alpha] ciphertext
                  -> CiphertextOnlyAttack key [Alpha] ciphertext
bruteForceEnglish = bruteForceWithDist englishDist

-- | Guess the key length given a ciphertext encoded using a poly-alphabetic
-- substitution cipher, i.e. a cipher defined using 'poly', assuming it
-- was encoded in English. The output is a list of 'Int's, sorted with the
-- likeliest key length at the head of the list, where each 'Int' is paired with
-- the average distance from English's frequency distribution. This should work
-- regardless of the underlying per-character cipher (since the underlying
-- cipher is necessarily a substitution).
guessPolyAlphaKeyLength :: [Int]
                        -- ^ List of key lengths to try
                        -> [Alpha]
                        -> [(Int, Float)]
guessPolyAlphaKeyLength keyLengths ciphertext =
  sortBy (comparing snd) $ zip keyLengths (map f keyLengths)
  where f = avg . map (d englishDist . getDist) . flip slices ciphertext

-- | Given an attack on a scheme produced by 'mono', lift it to an attack
-- on a scheme produced by 'poly' assuming we know the key length. Use in
-- conjunction with 'guessPolyAlphaKeyLength'.
breakPoly :: CiphertextOnlyAttack key [plainchar] [cipherchar]
          -- ^ Attack on mono cipher
          -> Int
          -- ^ Key length of poly cipher
          -> CiphertextOnlyAttack (LN.NonEmpty key) [plainchar] [cipherchar]
breakPoly attack keyLength ciphertext =
  let sliceAttacks = map attack (slices keyLength ciphertext)
      orderedKeysWithSlices = sequencePreferred 26 keyLength sliceAttacks
      combineKeysWithSlices keysWithSlices =
        (LN.fromList (fst <$> keysWithSlices), unSlices (snd <$> keysWithSlices))
      orderedAttacks = map combineKeysWithSlices orderedKeysWithSlices
  in orderedAttacks

-- | Brute-force, ciphertext-only attack on 'monoAlphaShift'.
breakMonoAlphaShift :: CiphertextOnlyAttack Int [Alpha] [Alpha]
breakMonoAlphaShift = bruteForce [0..25] monoAlphaShift

-- | Brute-force, English-biased ciphertext-only attack on 'monoAlphaShift'.
breakMonoAlphaShiftEnglish :: CiphertextOnlyAttack Int [Alpha] [Alpha]
breakMonoAlphaShiftEnglish = bruteForceEnglish [0..25] monoAlphaShift

-- | English-biased ciphertext-only attack on 'polyAlphaShiftCipher', given the
-- key length of the cipher. Use in conjunciton with 'guessPolyAlphaKeyLength'.
breakPolyAlphaShiftEnglish :: Int -> CiphertextOnlyAttack (LN.NonEmpty Int) [Alpha] [Alpha]
breakPolyAlphaShiftEnglish = breakPoly breakMonoAlphaShiftEnglish

-- | Known-plaintext attack on 'monoAlphaShift'. Assumes the input pairs are valid;
-- does not check for this. If the input list contains only pairs of empty
-- strings, this degenerates into a brute-force attack. Assuming any of the
-- input pairs contain nonempty strings, this is guaranteed to be correct for
-- any shift cipher, and only produces one result.
breakMonoAlphaShiftKnownPlaintext :: KnownPlaintextAttack Int [Alpha] [Alpha]
breakMonoAlphaShiftKnownPlaintext [] ciphertext = breakMonoAlphaShift ciphertext
breakMonoAlphaShiftKnownPlaintext (([],_):pairs) ciphertext =
  breakMonoAlphaShiftKnownPlaintext pairs ciphertext
-- NB: The below case only happens if the input was invalid.
breakMonoAlphaShiftKnownPlaintext ((_,[]):pairs) ciphertext =
  breakMonoAlphaShiftKnownPlaintext pairs ciphertext
breakMonoAlphaShiftKnownPlaintext ((p:ps,c:cs):_) ciphertext =
  let key = (fromEnum c - fromEnum p) `mod` 26
  in [(key, decrypt monoAlphaShift key ciphertext)]

-- | Attempts to break a mono-alphabetic substitution cipher given an expected
-- distribution of alphabetical characters. Needs improvement.
breakMonoAlphaSubst :: Distribution Alpha -> CiphertextOnlyAttack Permutation [Alpha] [Alpha]
breakMonoAlphaSubst refDist ciphertext =
  let dist = getDist ciphertext
      distLetters' = fst <$> sortOn (Down . snd) (Map.toList dist)
      distLetters = distLetters' ++ ([A .. Z] \\ distLetters')
      refLetters'  = fst <$> sortOn (Down . snd) (Map.toList refDist)
      refLetters = refLetters' ++ ([A .. Z] \\ refLetters')
      pairs = zip refLetters distLetters
      sigma = toPermutation $
        map (\a -> 1 + fromEnum (fromJust (lookup a pairs))) [A .. Z]
  in [(sigma, decrypt monoAlphaSubst sigma ciphertext)]
