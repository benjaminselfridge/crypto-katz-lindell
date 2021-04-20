{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators #-}

-- | Types for, and examples of, encryption schemes found in Katz/Lindell.
module Crypto.Schemes
  ( -- * Encryption and decryption
    EncryptFn
  , DecryptFn
    -- * Private key encryption
    -- ** Private key encryption schemes
  , PrivateKeyScheme(..)
  , generateKey'
    -- ** New schemes from old
  , iso
  , mono
  , poly
    -- ** Example private key ciphers
  , alphaShift
  , monoAlphaShift
  , polyAlphaShift
  , alphaSubst
  , monoAlphaSubst
  , polyAlphaSubst
  , oneTimePad
  ) where

import Crypto.Types

import Control.Lens (Iso', Prism', from, (^.), re, (^?))
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

-- | Generate a key with a security parameter of @undefined@. This is useful for
-- schemes that are known to ignore the security parameter (like a basic shift
-- or substitution cipher).
generateKey' :: forall key plaintext ciphertext m . MonadRandom m
             => PrivateKeyScheme key plaintext ciphertext -> m key
generateKey' = flip generateKey undefined

-- | Generate a 'PrivateKeyScheme' from an existing scheme by supplying
-- bidirectional mappings between the @key@, @plaintext@, and @ciphertext@
-- types. bijections between the key, plaintext, and ciphertext types.
--
-- Note the argument types:
-- * @Iso' key key'@, an isomorphism between @key@ and @key'@
-- * @Prism' plaintext plaintext'@, a reversible injective embedding of
--   @plaintext'@ into @plaintext@
-- * @Prism' ciphertext' ciphertext@, a reversible injective embedding of
--   @ciphertext@ into @ciphertext'
iso :: Iso' key key'
    -> Prism' plaintext plaintext'
    -> Prism' ciphertext' ciphertext
    -> PrivateKeyScheme key plaintext ciphertext
    -> PrivateKeyScheme key' plaintext' ciphertext'
iso kl pl cl s = PrivateKeyScheme
  { generateKey = \n -> do
      key <- generateKey s n
      return $ key ^. kl
  , encrypt = \key' plaintext' -> do
      ciphertext <- encrypt s (key' ^. from kl) (plaintext' ^. re pl)
      return $ ciphertext ^. re cl
  , decrypt = \key' ciphertext' ->
      let plaintext = decrypt s (key' ^. from kl) (fromJust $ ciphertext' ^? cl)
      in fromJust $ plaintext ^? pl
  }

-- | Given a 'PrivateKeyScheme' that operates on individual characters, lift
-- that scheme to one that operates on strings. The new scheme uses the same
-- @key@ type as the per-character scheme, and encrypts/decrypts by mapping the
-- input scheme's 'encrypt' and 'decrypt' functions over the strings.
mono :: PrivateKeyScheme key plainchar cipherchar
     -> PrivateKeyScheme key [plainchar] [cipherchar]
mono s = PrivateKeyScheme
  { generateKey = generateKey s
  , encrypt = traverse . encrypt s
  , decrypt = map . decrypt s
  }

-- | Given a 'PrivateKeyScheme' that operates on individual characters, generate
-- a new scheme that operates on strings. The new scheme uses a /list/ of
-- @key@s, and encrypts/decrypts by cycling through this list, applying each
-- @key@ to each character of plaintext. When we run out of keys, start over
-- with the original list.
--
-- The security parameter of the lifted scheme will determine the length of the
-- key produced by the 'generateKey' function. The 'Int' that is passed to this
-- function will be used as the security parameter that gets fed to the
-- 'generateKey' of the input scheme.
--
-- If the key length is non-positive, the key generation will throw a runtime
-- error.
poly :: PrivateKeyScheme key plaintext ciphertext
     -> Int
     -- ^ The security parameter to pass to the input scheme's
     -- key generator.
     -> PrivateKeyScheme (LN.NonEmpty key) [plaintext] [ciphertext]
poly s securityParam = PrivateKeyScheme
  { generateKey = \keyLength -> do
      ks <- replicateM keyLength (generateKey s securityParam)
      case LN.nonEmpty ks of
        Just key -> return key
        Nothing -> error msg
  , encrypt = zipWithM (encrypt s) . cycle . toList
  , decrypt = zipWith (decrypt s) . cycle . toList
  }

  where msg = "generateKey called with non-positive key length"

-- | Shift cipher for single 'Alpha'. This is used to define
-- 'monoAlphaShift' and 'polyAlphaShift'. The key generator ignores
-- its input.
alphaShift :: PrivateKeyScheme Int Alpha Alpha
alphaShift = PrivateKeyScheme
  { generateKey = const $ uniform [0 .. 25]
  , encrypt = \key -> return . shiftAlpha key
  , decrypt = shiftAlpha . negate
  }

-- | Mono-alphabetic shift cipher. The key is an 'Int' between 0 and 25
-- (inclusive), and we shift each character by that amount to encrypt.
--
-- @
-- monoAlphaShift == mono alphaShift
-- @
monoAlphaShift :: PrivateKeyScheme Int [Alpha] [Alpha]
monoAlphaShift = mono alphaShift

-- | Poly-alphabetic shift cipher, also known as Vigenère cipher. This promotes
-- the normal 'alphaShift' to operate on lists of keys.
--
-- @
-- polyAlphaShift == poly alphaShift undefined
-- @
polyAlphaShift :: PrivateKeyScheme (LN.NonEmpty Int) [Alpha] [Alpha]
polyAlphaShift = poly alphaShift undefined

-- | Substitution cipher for single 'Alpha'. This is used to define
-- 'monoAlphaSubst' and 'polyAlphaSubst'. The key generator ignores
-- its input.
alphaSubst :: PrivateKeyScheme Permutation Alpha Alpha
alphaSubst = PrivateKeyScheme
  { generateKey = const $ fst . randomPermutation 26 . mkStdGen <$> getRandom
  , encrypt = \key -> return . permuteAlpha key
  , decrypt = permuteAlpha . inverse
  }

-- | Mono-alphabetic substitution cipher. The key is a 'Permutation' of the
-- alphabet, and we apply the permutation to each character in the input to
-- encrypt.
--
-- @
-- monoAlphaSubst == mono alphaSubst
-- @
monoAlphaSubst :: PrivateKeyScheme Permutation [Alpha] [Alpha]
monoAlphaSubst = mono alphaSubst

-- | Poly-alphabetic substitution cipher. This promotes the normal
-- 'alphaSubst' to operate on lists of keys.
--
-- @
-- polyAlphaSubst == poly alphaSubst undefined
-- @
polyAlphaSubst :: PrivateKeyScheme (LN.NonEmpty Permutation) [Alpha] [Alpha]
polyAlphaSubst = poly alphaSubst undefined

-- | One-time pad on bitvectors of a given length.
oneTimePad :: BV.NatRepr w -> PrivateKeyScheme (BV.BV w) (BV.BV w) (BV.BV w)
oneTimePad w = PrivateKeyScheme
  { generateKey = const $ BV.mkBV w <$> getRandom
  , encrypt = \key -> return . BV.xor key
  , decrypt = BV.xor
  }
