{-# LANGUAGE GADTs #-}
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
  , trans, transN, transKey, transPlaintext, transCiphertext
  , compose
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

import Control.Lens (Iso', Prism', from, (^.), re, (^?!))
import Control.Monad.Random
import qualified Data.BitVector.Sized as BV
import Data.Foldable (toList)
import qualified Data.List.NonEmpty as LN
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
--   decrypt s k (encrypt s k p) == return p
-- @
data PrivateKeyScheme n key plaintext ciphertext = PrivateKeyScheme
  { generateKey :: forall m . MonadRandom m => n -> m key
    -- ^ Generate a random key from a given security parameter ('Int').
  , encrypt :: key -> EncryptFn plaintext ciphertext
    -- ^ Encrypt plaintext with a given key.
  , decrypt :: key -> DecryptFn plaintext ciphertext
    -- ^ Decrypt plaintext with a given key.
  }

-- | Generate a key with a security parameter of @()@. This is useful for
-- schemes that ignore the security parameter (like a basic shift or
-- substitution cipher).
generateKey' :: forall key plaintext ciphertext m . MonadRandom m
             => PrivateKeyScheme () key plaintext ciphertext -> m key
generateKey' = flip generateKey ()

-- | Generate a 'PrivateKeyScheme' from an existing scheme by supplying
-- bidirectional mappings between the @key@, @plaintext@, and @ciphertext@
-- types.
--
-- Note the argument types:
--
--   * @n' -> n@, any map from security parameter @n'@ to @n@
--
--   * @Iso' key key'@, an isomorphism between @key@ and @key'@
--
--   * @Prism' plaintext plaintext'@, a reversible injective embedding of
--     @plaintext'@ into @plaintext@
--
--   * @Prism' ciphertext' ciphertext@, a reversible injective embedding of
--     @ciphertext@ into @ciphertext'@
--
-- The need for these mappings is derived from the requirement that the derived
-- scheme must be a correct encryption scheme, i.e. we must know that for all
-- @p' :: plaintext'@ and @k' :: key'@,
--
-- @
-- decrypt s' key' (encrypt s' key' p') == return p'.
-- @
trans :: (n' -> n)
      -- ^ map @n' -\> n@
      -> Iso' key key'
      -- ^ bijection @key \<-\> key'@
      -> Prism' plaintext plaintext'
      -- ^ invertible embedding @plaintext' -\> plaintext@
      -> Prism' ciphertext' ciphertext
      -- ^ invertible embedding @ciphertext -\> ciphertext'@
      -> PrivateKeyScheme n key plaintext ciphertext
      -> PrivateKeyScheme n' key' plaintext' ciphertext'
trans nl kl pl cl s = PrivateKeyScheme
  { generateKey = \n' -> do
      key <- generateKey s (nl n')
      return $ key ^. kl
  , encrypt = \key' plaintext' -> do
      ciphertext <- encrypt s (key' ^. from kl) (plaintext' ^. re pl)
      return $ ciphertext ^. re cl
  , decrypt = \key' ciphertext' ->
      let plaintext = decrypt s (key' ^. from kl) (ciphertext' ^?! cl)
      in plaintext ^?! pl
  }

-- | 'trans' but only for the security parameter @n@.
transN :: (n' -> n)
        -> PrivateKeyScheme n key plaintext ciphertext
        -> PrivateKeyScheme n' key plaintext ciphertext
transN f = trans f id id id

-- | 'trans' but only for the @key@.
transKey :: Iso' key key'
         -> PrivateKeyScheme n key plaintext ciphertext
         -> PrivateKeyScheme n key' plaintext ciphertext
transKey f = trans id f id id

-- | 'trans' but only for the @plaintext@.
transPlaintext :: Prism' plaintext plaintext'
               -> PrivateKeyScheme n key plaintext ciphertext
               -> PrivateKeyScheme n key plaintext' ciphertext
transPlaintext f = trans id id f id

-- | 'trans' but only for the @ciphertext@.
transCiphertext :: Prism' ciphertext' ciphertext
                -> PrivateKeyScheme n key plaintext ciphertext
                -> PrivateKeyScheme n key plaintext ciphertext'
transCiphertext = trans id id id

-- | Compose two encryption schemes.
compose :: ciphertext1 ~ plaintext2
        => PrivateKeyScheme n1 key1 plaintext1 ciphertext1
        -> PrivateKeyScheme n2 key2 plaintext2 ciphertext2
        -> PrivateKeyScheme (n1, n2) (key1, key2) plaintext1 ciphertext2
compose s1 s2 = PrivateKeyScheme
  { generateKey = \(n1, n2) -> (,) <$> generateKey s1 n1 <*> generateKey s2 n2
  , encrypt = \(key1, key2) -> encrypt s2 key2 <=< encrypt s1 key1
  , decrypt = \(key1, key2) -> decrypt s1 key1 . decrypt s2 key2
  }

-- | Given a 'PrivateKeyScheme' that operates on individual characters, lift
-- that scheme to one that operates on strings. The new scheme uses the same
-- @key@ type as the per-character scheme, and encrypts/decrypts by mapping the
-- input scheme's 'encrypt' and 'decrypt' functions over the strings.
mono :: PrivateKeyScheme n key plainchar cipherchar
     -> PrivateKeyScheme n key [plainchar] [cipherchar]
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
-- If the key length is non-positive, the key generation will throw a runtime
-- error.
poly :: PrivateKeyScheme n key plaintext ciphertext
     -> PrivateKeyScheme (Int, n) (LN.NonEmpty key) [plaintext] [ciphertext]
poly s = PrivateKeyScheme
  { generateKey = \(keyLength, n) -> do
      ks <- replicateM keyLength (generateKey s n)
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
alphaShift :: PrivateKeyScheme () Int Alpha Alpha
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
monoAlphaShift :: PrivateKeyScheme () Int [Alpha] [Alpha]
monoAlphaShift = mono alphaShift

-- | Poly-alphabetic shift cipher, also known as Vigenère cipher. This promotes
-- the normal 'alphaShift' to operate on lists of keys.
--
-- @
-- polyAlphaShift == poly alphaShift undefined
-- @
polyAlphaShift :: PrivateKeyScheme Int (LN.NonEmpty Int) [Alpha] [Alpha]
polyAlphaShift = transN (,()) $ poly alphaShift

-- | Substitution cipher for single 'Alpha'. This is used to define
-- 'monoAlphaSubst' and 'polyAlphaSubst'. The key generator ignores
-- its input.
alphaSubst :: PrivateKeyScheme () Permutation Alpha Alpha
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
monoAlphaSubst :: PrivateKeyScheme () Permutation [Alpha] [Alpha]
monoAlphaSubst = mono alphaSubst

-- | Poly-alphabetic substitution cipher. This promotes the normal
-- 'alphaSubst' to operate on lists of keys.
--
-- @
-- polyAlphaSubst == poly alphaSubst undefined
-- @
polyAlphaSubst :: PrivateKeyScheme Int (LN.NonEmpty Permutation) [Alpha] [Alpha]
polyAlphaSubst = transN (,()) $ poly alphaSubst

-- | One-time pad on bitvectors of a given length.
oneTimePad :: BV.NatRepr w -> PrivateKeyScheme () (BV.BV w) (BV.BV w) (BV.BV w)
oneTimePad w = PrivateKeyScheme
  { generateKey = const $ BV.mkBV w <$> getRandom
  , encrypt = \key -> return . BV.xor key
  , decrypt = BV.xor
  }
