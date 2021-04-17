{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Types for, and examples of, encryption schemes found in Katz/Lindell.
module Crypto.Schemes
  ( -- * Encryption and decryption
    EncryptFn
  , DecryptFn
    -- * Private key encryption
    -- ** Private key encryption schemes
  , PrivateKeyScheme(..)
  , generateKey1
    -- ** New schemes from old
  , liftCharCipher
  , cycleKeyCipher
    -- ** Example private key ciphers
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

-- | Encryption function mapping @plaintext@ to @ciphertext@. Note that
-- encryption can be probabilistic (but doesn't have to be).
type EncryptFn plaintext ciphertext =
  forall m . MonadRandom m => plaintext -> m ciphertext

-- | Decryption function mapping @ciphertext@ to @plaintext@. Note that
-- decryption is deterministic.
type DecryptFn plaintext ciphertext = ciphertext -> plaintext

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
  , encrypt :: key -> EncryptFn plaintext ciphertext
    -- ^ Encrypt plaintext with a given key.
  , decrypt :: key -> DecryptFn plaintext ciphertext
    -- ^ Decrypt plaintext with a given key.
  }

-- | Generate a key with a security parameter of @1@. This is mostly useful for
-- schemes that are known to ignore the security parameter (like a basic shift
-- or substitution cipher).
generateKey1 :: forall key plaintext ciphertext m . MonadRandom m
             => PrivateKeyScheme key plaintext ciphertext -> m key
generateKey1 = flip generateKey 1

-- | Given a 'PrivateKeyScheme' that maps invidual characters of @plaintext@ to
-- individual characters of @ciphertext@, lift that scheme to one that operates
-- on strings. The new scheme uses the same @key@ type as the per-character
-- scheme, and encrypts/decrypts by mapping the input scheme's 'encrypt' and
-- 'decrypt' functions over the strings.
liftCharCipher :: PrivateKeyScheme key plainchar cipherchar
               -> PrivateKeyScheme key [plainchar] [cipherchar]
liftCharCipher s = PrivateKeyScheme
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
cycleKeyCipher :: PrivateKeyScheme key plaintext ciphertext
               -> Int
               -- ^ The security parameter to pass to the input scheme's
               -- key generator.
               -> PrivateKeyScheme (LN.NonEmpty key) [plaintext] [ciphertext]
cycleKeyCipher s securityParam = PrivateKeyScheme
  { generateKey = \keyLength -> do
      ks <- replicateM keyLength (generateKey s securityParam)
      case LN.nonEmpty ks of
        Just key -> return key
        Nothing -> error msg
  , encrypt = zipWithM (encrypt s) . cycle . toList
  , decrypt = zipWith (decrypt s) . cycle . toList
  }

  where msg = "generateKey called with non-positive key length"

-- | Shift cipher for single 'Alpha'. This is used to define 'shiftCipher' and
-- 'vigenereCipher'. The key generator ignores its input.
shiftCipher' :: PrivateKeyScheme Int Alpha Alpha
shiftCipher' = PrivateKeyScheme
  { generateKey = const $ uniform [0 .. 25]
  , encrypt = \key -> return . shiftAlpha key
  , decrypt = shiftAlpha . negate
  }

-- | Shift cipher. The key is an 'Int' between 0 and 25 (inclusive), and we
-- shift each character by that amount to encrypt.
--
-- @
-- shiftCipher == liftCharCipher shiftCipher'
-- @
shiftCipher :: PrivateKeyScheme Int [Alpha] [Alpha]
shiftCipher = liftCharCipher shiftCipher'

-- | Vigenère cipher. This promotes the normal 'shiftCipher' to operate on lists
-- of keys.
--
-- @
-- vigenereCipher = cycleKeyCipher shiftCipher' undefined
-- @
vigenereCipher :: PrivateKeyScheme (LN.NonEmpty Int) [Alpha] [Alpha]
vigenereCipher = cycleKeyCipher shiftCipher' undefined

-- | Substitution cipher for single 'Alpha'. This is used to define
-- 'substCipher'. The key generator ignores its input.
substCipher' :: PrivateKeyScheme Permutation Alpha Alpha
substCipher' = PrivateKeyScheme
  { generateKey = const $ fst . randomPermutation 26 . mkStdGen <$> getRandom
  , encrypt = \key -> return . permuteAlpha key
  , decrypt = permuteAlpha . inverse
  }

-- | Substitution cipher. They key is a 'Permutation' on the alphabet, and we
-- simply apply the permutation to encrypt.
substCipher :: PrivateKeyScheme Permutation [Alpha] [Alpha]
substCipher = liftCharCipher substCipher'

-- | One-time pad on bitvectors of a given length.
oneTimePad :: BV.NatRepr w -> PrivateKeyScheme (BV.BV w) (BV.BV w) (BV.BV w)
oneTimePad w = PrivateKeyScheme
  { generateKey = const $ BV.mkBV w <$> getRandom
  , encrypt = \key -> return . BV.xor key
  , decrypt = BV.xor
  }
