{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}

-- | Types for, and examples of, encryption schemes found in Katz/Lindell.
module Crypto.Schemes
  ( -- * Private key encryption schemes
    PrivateKeyScheme(..)
  , generateKey1
    -- * New schemes from old
  , listScheme
  , cycleKeyScheme
    -- * Example private key ciphers
  , shiftCipher'
  , shiftCipher
  , substCipher'
  , substCipher
  , vigenereCipher
  , oneTimePad
  ) where

import Crypto.Types

import Control.Monad (zipWithM)
import Control.Monad.Random
import qualified Data.BitVector.Sized as BV
import Data.Foldable (toList)
import qualified Data.List.NonEmpty as LN
import Data.Maybe (fromJust)
import Math.Combinat.Permutations

-- | Private key scheme, as defined in Katz/Lindell page 60 (Definition 3.7),
-- but with generalized keys, plaintext, and ciphertext types.
--
-- Note that, for scheme @s@ to be valid, we require that for all keys @k@ and
-- messages @p@:
--
-- @
--   decrypt s k (encrypt s k m) == m
-- @
data PrivateKeyScheme key plaintext ciphertext = PrivateKeyScheme
  { generateKey :: forall m . MonadRandom m => Int -> m key
    -- ^ Generate a random key from a given security parameter ('Int').
  , encrypt :: forall m . MonadRandom m => key -> plaintext -> m ciphertext
    -- ^ Encrypt plaintext with a given key. Note that encryption can be
    -- probabilistic (but doesn't have to be).
  , decrypt :: key -> ciphertext -> plaintext
    -- ^ Decrypt plaintext with a given key. Decryption is deterministic.
  }

-- | Generate a key with a security parameter of @1@.
generateKey1 :: forall key plaintext ciphertext m . MonadRandom m
             => PrivateKeyScheme key plaintext ciphertext -> m key
generateKey1 = flip generateKey 1

-- | Lift a 'PrivateKeyScheme' to operate on lists of the @plaintext@ and
-- @ciphertext@ types. The @key@ type doesn't change; we simply apply the same
-- key to each element of the lists. The resulting scheme is by definition
-- length-preserving on both encryption and decryption.
listScheme :: PrivateKeyScheme key plaintext ciphertext
           -> PrivateKeyScheme key [plaintext] [ciphertext]
listScheme s = PrivateKeyScheme
  { generateKey = generateKey s
  , encrypt = traverse . encrypt s
  , decrypt = map . decrypt s
  }

-- | Lift a 'PrivateKeyScheme' to operate on lists of the @plaintext@ and
-- @ciphertext@ types. The @key@ type becomes a nonempty list of the original
-- @key@. We encrypt using each key in the list, one-at-a-time, for each element
-- in the @plaintext@ list. When we run out of @key@ values, we start over with
-- the original list.
--
-- The security parameter of the resulting scheme will determine the length of
-- the key produced by the 'generateKey' function. The 'Int' that is passed to
-- this function will be used as the security parameter that gets fed to the
-- 'generateKey' of the input scheme.
--
-- If the key length is non-positive, the key generation will throw a runtime
-- error.
cycleKeyScheme :: PrivateKeyScheme key plaintext ciphertext
               -> Int
               -- ^ The security parameter to pass to the input scheme's
               -- key generator.
               -> PrivateKeyScheme (LN.NonEmpty key) [plaintext] [ciphertext]
cycleKeyScheme s securityParam = PrivateKeyScheme
  { generateKey = \keyLength -> do
      ks <- replicateM keyLength (generateKey s securityParam)
      case LN.nonEmpty ks of
        Just key -> return key
        Nothing -> error msg
  , encrypt = zipWithM (encrypt s) . cycle . toList
  , decrypt = zipWith (decrypt s) . cycle . toList
  }

  where msg = "generateKey called with non-positive key length"

shiftAlpha :: Int -> Alpha -> Alpha
shiftAlpha i = toEnum . (`mod` 26) . (+i) . fromEnum

-- | Shift cipher for single 'Alpha'. This is used to define 'shiftCipher' and
-- 'vigenereCipher'. The key generator ignores its input.
shiftCipher' :: PrivateKeyScheme Int Alpha Alpha
shiftCipher' = PrivateKeyScheme
  { generateKey = const $ getRandomR (0, 25)
  , encrypt = \key -> return . shiftAlpha key
  , decrypt = \key -> shiftAlpha (negate key)
  }

-- | Shift cipher. The key is an 'Int' between 0 and 25 (inclusive), and we
-- shift each character by that amount to encrypt.
--
-- @
-- shiftCipher == listScheme shiftCipher'
-- @
shiftCipher :: PrivateKeyScheme Int [Alpha] [Alpha]
shiftCipher = listScheme shiftCipher'

-- | Vigenère cipher. This promotes the normal 'shiftCipher' to operate on lists
-- of keys.
--
-- @
-- vigenereCipher = cycleKeyScheme shiftCipher' undefined
-- @
vigenereCipher :: PrivateKeyScheme (LN.NonEmpty Int) [Alpha] [Alpha]
vigenereCipher = cycleKeyScheme shiftCipher' undefined

-- | Substitution cipher for single 'Alpha'. This is used to define
-- 'substCipher'. The key generator ignores its input.
substCipher' :: PrivateKeyScheme Permutation Alpha Alpha
substCipher' = PrivateKeyScheme
  { generateKey = const $ (fst . randomPermutation 26 . mkStdGen) <$> getRandom
  , encrypt = \key -> return . fromJust . flip lookup (zip [A .. Z] (permuteList key [A .. Z]))
  , decrypt = \key -> fromJust . flip lookup (zip (permuteList key [A .. Z]) [A .. Z])
  }

-- | Substitution cipher. They key is a 'Permutation' on the alphabet, and we
-- simply apply the permutation to encrypt.
substCipher :: PrivateKeyScheme Permutation [Alpha] [Alpha]
substCipher = listScheme substCipher'

-- | One-time pad on bitvectors of a given length.
oneTimePad :: BV.NatRepr w -> PrivateKeyScheme (BV.BV w) (BV.BV w) (BV.BV w)
oneTimePad w = PrivateKeyScheme
  { generateKey = const $ BV.mkBV w <$> getRandom
  , encrypt = \k -> return . BV.xor k
  , decrypt = BV.xor
  }
