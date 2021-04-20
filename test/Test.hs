{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Main where

import Crypto.Schemes

import Control.Category
import qualified Data.BitVector.Sized as BV
import Data.Invertible.Bijection
import Data.Parameterized.NatRepr
import GHC.TypeNats
import Test.QuickCheck
import Test.QuickCheck.Monadic
import Test.Tasty
import Test.Tasty.QuickCheck

import Prelude hiding (id, (.))

newtype KeyLength = KeyLength Int
  deriving (Eq, Show)

instance Arbitrary KeyLength where
  arbitrary = KeyLength <$> chooseInt (1, 20)

newtype ABV w = ABV { unABV :: BV.BV w }
  deriving (Show, Eq)

instance KnownNat w => Arbitrary (ABV w) where
  arbitrary = ABV . BV.mkBV knownNat <$>
    choose (0, maxUnsigned (knownNat :: NatRepr w))

prop_encryptDecrypt :: Eq plaintext
                    => PrivateKeyScheme key plaintext ciphertext
                    -> KeyLength
                    -> plaintext
                    -> Property
prop_encryptDecrypt s (KeyLength n) plaintext = monadicIO $ do
  key <- run $ generateKey s n
  ciphertext <- run $ encrypt s key plaintext
  assert $ decrypt s key ciphertext == plaintext

prop_encryptDecrypt' :: Eq plaintext
                     => PrivateKeyScheme key plaintext ciphertext
                     -> plaintext
                     -> Property
prop_encryptDecrypt' = flip prop_encryptDecrypt (KeyLength undefined)

tests :: TestTree
tests = testGroup "Encrypt/Decrypt"
  [ testProperty "mono-alphabetic shift" $
    prop_encryptDecrypt' monoAlphaShift
  , testProperty "poly-alphabetic shift" $
    prop_encryptDecrypt polyAlphaShift
  , testProperty "mono-alphabetic substitution" $
    prop_encryptDecrypt' monoAlphaSubst
  , testProperty "poly-alphabetic substitution" $
    prop_encryptDecrypt polyAlphaSubst
  , testProperty "one-time pad" $
    prop_encryptDecrypt $
    iso id (ABV :<->: unABV) id (oneTimePad (knownNat @32))
  ]

main :: IO ()
main = defaultMain tests
