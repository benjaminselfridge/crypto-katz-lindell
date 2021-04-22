{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators #-}

{-|

Module: Crypto.Schemes
Description: Private key encryption schemes
Copyright: (c) Ben Selfridge, 2021

This module contains the types and combinators for defining and using
private-key encryption schemes. The basic type exported by this module is

@
data PrivateKeyScheme n k p c
@

where @k@ is the scheme's key type, @p@ is the plaintext type, @c@ is the
ciphertext type, and @n@ is the /security parameter/ that is input to the key
generation function.

Let's look at an example of how to use this module in a ghci session. First
we'll include some necessary imports and extensions for the example.

>>> :set -XOverloadedStrings -XTupleSections -XDataKinds -XTypeApplications
>>> import qualified Data.BitVector.Sized as BV
>>> import Data.ByteString.Internal (c2w, w2c)
>>> import qualified Data.ByteString.Lazy as BS
>>> import qualified Data.List.NonEmpty as LN
>>> import Data.Word
>>> import Control.Lens
>>> import Math.Combinat.Permutations
>>> import Crypto.Schemes

Consider the type of 'oneTimePad', exported by this module:

>>> :t oneTimePad
oneTimePad
  :: BV.NatRepr w
     -> PrivateKeyScheme () (BV.BV w) (BV.BV w) (BV.BV w)

This takes a width parameter, @w@, and generates an encryption scheme with key
type, plaintext type, and ciphertext type @BV w@. Note that it has no security
parameter; @oneTimePad@ does not need any extra information to know how to
generate a key. Let's specialize @oneTimePad@ to operate on bytes:

>>> otp8 = oneTimePad (BV.knownNat @8)
>>> :t otp8
otp8 :: PrivateKeyScheme () (BV.BV 8) (BV.BV 8) (BV.BV 8)

We can use it to generate a key, and to encrypt and decrypt a message with that
key:

>>> k <- generateKey otp8
>>> msg = BV.mkBV (BV.knownNat @8) 123
>>> msg' <- encrypt otp8 k msg
>>> msg'
BV 203
>>> decrypt otp8 k msg
BV 123

This is a bit limiting. What if we want to dynamically set the key length, and
operate on bytestrings instead of bitvectors? We can actually derive such a
scheme from this basic one through a series of transformations. That is, we will
go from

@
otp8 :: PrivateKeyScheme () (BV.BV 8) (BV.BV 8) (BV.BV 8)
@

to

@
otpBS :: PrivateKeyScheme Int BS.ByteString BS.ByteString BS.ByteString
@

(The @Int@ in the second type signature is the key length.)

The first step in this transformation is to change all the @BV@s to words. We
will do this with the help of the 'trans' function, as well as a simple
'Control.Lens' isomorphism:

>>> bvW8 = iso (fromInteger . BV.asUnsigned) BV.word8 :: Iso' (BV.BV 8) Word8
>>> otpW8 = trans id bvW8 bvW8 (from bvW8) otp8
>>> :t otpW8
otpW8 :: PrivateKeyScheme () Word8 Word8 Word8

Next, we will use the 'poly' combinator to lift @otpW8@ to operate on lists of
'Data.Word.Word8's, so that the key becomes a list as well, and we cycle through
the key to perform encryption on each 'Data.Word.Word8':

>>> otpW8s = transN (,()) $ poly otpW8
otpW8s
  :: PrivateKeyScheme Int (LN.NonEmpty Word8) [Word8] [Word8]

(The use of @transN (,())@ just gets rid of an unnecessary @()@ in the security
parameter type.)

Now, the key type requires the key to be nonempty. This is reasonable, since we
need to have /some/ key to use with the original encryption scheme. However,
that makes things a bit annoying for us, since ByteStrings can be empty. We will
solve this problem by cheating. First, we define an "isomorphism" between
@NonEmpty Word8@ and @[Word8]@, and then we use it to change the key type:

>>> ne = iso LN.toList LN.fromList :: Iso' (LN.NonEmpty Word8) [Word8]
>>> otpW8s' = transKey ne otpW8s
>>> :t otpW8s'
otpW8s' :: PrivateKeyScheme Int [Word8] [Word8] [Word8]

We are almost there. We just need one more isomorphism, mapping @[Word8]@ to
'Data.ByteString.Lazy.ByteString':

>>> w8BS = iso BS.pack BS.unpack :: Iso' [Word8] BS.ByteString
>>> otpBS = trans id w8BS w8BS (from w8BS) otpW8s'
otpBS
  :: PrivateKeyScheme Int BS.ByteString BS.ByteString BS.ByteString

Now, our original encryption scheme (which only operated on fixed-width
bitvectors) has been generalized to work on bytestrings as well, and we can
generate a key of any length we want:

>>> k <- generateKey otpBS 128
>>> k
"#2\156\128\248\DC1U)n\166\198\162\&2A\212\n&\NULb1\132!\155?5\255j\182\ETB\219\187\205\224~n\212\172\212\ETB\137\235\228P\220q\192\a\209\226\234\208\\\165j\172\177\\oD\154\141\254W\ETB?\138\141\"\246\162\rS7Y\ACK\DC3\150\210\196\172?\ESC\175R\ETBk\154\SII\143\149\176R.\132;\148C\161\182\192\248\249`\160\165\\\ETB\229\&9\231\172k4\141\211\242\161\146\164\213\203*5\247\143\232B"
>>> msg = "This message is fewer than 128 characters, so if this is the only message I send, it will be perfectly secret!" :: BS.ByteString
>>> msg' <- encrypt otpBS k msg
>>> msg'
"wZ\245\243\216|0Z\GS\199\161\199\DC2(\167*@e\NAKT\246\SOH\239WT\145J\135%\227\155\174\136\US\FS\181\207\160r\251\152\200p\175\RS\224n\183\194\158\184\&5\214J\197\194|\ESC,\255\173\145\&9{F\170\224G\133\209l4RyO3\229\183\170\200\DC3;\198&7\FS\243c%\175\247\213r^\225I\242&\194\194\172\129\217\DC3\197\198.r\145\CAN"
>>> decrypt otpBS k msg'
"This message is fewer than 128 characters, so if this is the only message I send, it will be perfectly secret!"

We can also /compose/ two schemes. The following two schemes are exported by
this module:

@
polyAlphaShift :: PrivateKeyScheme Int (LN.NonEmpty Int) [Alpha] [Alpha]
monoAlphaSubst :: PrivateKeyScheme () Permutation [Alpha] [Alpha]
@

It would be nice if we could compose the two schemes to obtain the benefits of
both. Fortunately, we can:

>>> cipher = transN (,()) $ compose polyAlphaShift monoAlphaSubst
>>> :t cipher
cipher
  :: PrivateKeyScheme
       Int (LN.NonEmpty Int, Permutation) [Alpha] [Alpha]

The resulting @encrypt@ function first performs a poly-alphabetic shift to the
plaintext, followed by a mono-alphabetic substitution. The combined scheme uses
a pair of keys, each used for a separate encryption step.

-}
module Crypto.Schemes
  ( -- * Encryption and decryption
    EncryptFn
  , DecryptFn
    -- * Private key encryption
    -- ** Private key encryption schemes
  , PrivateKeyScheme(..)
  , generateKey'
    -- ** Scheme combinators
  , substFromAction, substFromList
  , shiftFromAction, shiftFromList
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
import Crypto.Utils

import Control.Lens (Iso', Prism', from, (^.), re, (^?!))
import Data.Maybe (fromJust)
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
--   decrypt s k \<$\> encrypt s k p == return p
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
             => PrivateKeyScheme () key plaintext ciphertext
             -- ^
             -> m key
generateKey' = flip generateKey ()

-- | Build a simple shift cipher given a way to apply a shift int to the text.
shiftFromAction :: Int
                -- ^ The number of elements of @t@.
                -> (Int -> t -> t)
                -- ^ The shifting function @f@. This must satisfy @f (-i) (f i t) == t@
                -- for all @t@.
                -> PrivateKeyScheme () Int t t
shiftFromAction i f = PrivateKeyScheme
  { generateKey = const $ uniform [0 .. i-1]
  , encrypt = \key -> return . f key
  , decrypt = f . negate
  }

-- | Build a simple shift cipher given the universe of text. Encrypting every
-- message is linear in the size of the universe.
shiftFromList :: Eq t
              => [t]
              -- ^ The entire (finite) universe of @t@, in order.
              -> PrivateKeyScheme () Int t t
shiftFromList u = shiftFromAction (length u) $ \key p ->
  fromJust $ lookup p $ zip u (rotate key u)

-- | Build a simple substitution cipher given a way to apply a permutation to
-- the text. Encrypting every message takes as long as the permutation action
-- supplied.
substFromAction :: Int
                -- ^ The number of elements of @t@.
                -> (Permutation -> t -> t)
                -- ^ A method for applying a permutation to the text. This
                -- should expect permutations on the number of elements supplied
                -- as the first argument to this function. Mathematically, this
                -- must be a group action on the set @t@ to get a valid
                -- substitution cipher.
                -> PrivateKeyScheme () Permutation t t
substFromAction n apply = PrivateKeyScheme
  { generateKey = const $ fst . randomPermutation n . mkStdGen <$> getRandom
  , encrypt = \key -> return . apply key
  , decrypt = \key -> apply (inverse key)
  }

-- | Build a simple substitution cipher given the universe of text. Encrypting
-- every message is linear in the size of the universe.
substFromList :: Eq t
              => [t]
              -- ^ The entire (finite) universe of @t@, in order.
              -> PrivateKeyScheme () Permutation t t
substFromList u = substFromAction (length u) $ \key p ->
  fromJust $ lookup p $ zip u (permuteList key u)

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
      (decrypt s (key' ^. from kl) (ciphertext' ^?! cl)) ^?! pl
  }

-- | 'trans' but only for the security parameter @n@.
transN :: (n' -> n)
       -- ^
       -> PrivateKeyScheme n key plaintext ciphertext
       -> PrivateKeyScheme n' key plaintext ciphertext
transN f = trans f id id id

-- | 'trans' but only for the @key@.
transKey :: Iso' key key'
         -- ^
         -> PrivateKeyScheme n key plaintext ciphertext
         -> PrivateKeyScheme n key' plaintext ciphertext
transKey f = trans id f id id

-- | 'trans' but only for the @plaintext@.
transPlaintext :: Prism' plaintext plaintext'
               -- ^
               -> PrivateKeyScheme n key plaintext ciphertext
               -> PrivateKeyScheme n key plaintext' ciphertext
transPlaintext f = trans id id f id

-- | 'trans' but only for the @ciphertext@.
transCiphertext :: Prism' ciphertext' ciphertext
                -- ^
                -> PrivateKeyScheme n key plaintext ciphertext
                -> PrivateKeyScheme n key plaintext ciphertext'
transCiphertext = trans id id id

-- | Compose two encryption schemes.
compose :: ciphertext1 ~ plaintext2
        => PrivateKeyScheme n1 key1 plaintext1 ciphertext1
        -- ^
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
     -- ^
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
     -- ^
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
alphaShift = shiftFromAction 26 shiftAlpha

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
-- polyAlphaShift == transN (,()) $ poly alphaShift
-- @
polyAlphaShift :: PrivateKeyScheme Int (LN.NonEmpty Int) [Alpha] [Alpha]
polyAlphaShift = transN (,()) $ poly alphaShift

-- | Substitution cipher for single 'Alpha'. This is used to define
-- 'monoAlphaSubst' and 'polyAlphaSubst'. The key generator ignores
-- its input.
alphaSubst :: PrivateKeyScheme () Permutation Alpha Alpha
alphaSubst = substFromAction 26 permuteAlpha

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
-- polyAlphaSubst == transN (,()) $ poly alphaSubst
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
