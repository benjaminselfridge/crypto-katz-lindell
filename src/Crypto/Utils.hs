{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE QuantifiedConstraints #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

-- | Helper functions.
module Crypto.Utils
  ( slices
  , unSlices
  , avg
  , sequencePreferred
  , rotate
  -- * Distributions and related functions
  , Distribution
  , getDist
  , NDistribution
  , getNDist
  , englishDist
  , ioc
  , d
  , d'
  -- * Ngrams and related functions
  , NgramCount
  , ngrams
  , ngramsFromFile
  -- * Choice (generalization of 'Either')
  , Choice(..)
  , choice
  , choose
  , isChoice
  , fromChoice
  , partitionChoices
  , ChoiceList(..)
  ) where

import Crypto.Types

import qualified Data.Kind as K
import Data.List (transpose, permutations, nub, tails)
import Data.List.Split (chunksOf, splitOn)
import qualified Data.Map as Map
import Data.Maybe (mapMaybe)
import qualified Data.Parameterized.List as PL
import Data.Parameterized.Classes
import Data.Parameterized.TraversableFC
import Data.Proxy
import Math.Combinat.Compositions

-- | Generalization of 'Either' for an arbitrary list of types.
data Choice (f :: k -> K.Type) (tps :: [k]) where
  Choice :: PL.Index tps tp -> f tp -> Choice f tps

instance FunctorFC Choice where
  fmapFC f (Choice i a) = Choice i (f a)

instance FoldableFC Choice where
  foldrFC f b (Choice _ a) = f a b

instance TraversableFC Choice where
  traverseFC f (Choice i a) = Choice i <$> f a

deriving instance (forall tp . Show (f tp)) => Show (Choice f tps)
instance (forall tp . Show (f tp)) => ShowF (Choice f)

-- | Case analysis for the 'Choice' type. Analogous to 'either'.
choice :: (forall tp . f tp -> c) -> Choice f tps -> c
choice f (Choice _ a) = f a

-- | Extracts from a list of 'Choice' all the elements of a particular index.
-- All such elements are extracted in order. Analogous to 'Data.Either.lefts'
-- and 'Data.Either.rights'.
choose :: PL.Index tps tp -> [Choice f tps] -> [f tp]
choose _ [] = []
choose ix (Choice ix' a : cs)
  | Just Refl <- ix `testEquality` ix' = a : choose ix cs
  | otherwise = choose ix cs

-- | Returns 'True' if the given value is an element of a particular choice
-- index, 'False' otherwise. Analogous to 'Data.Either.isLeft' and
-- 'Data.Either.isRight'.
isChoice :: PL.Index tps tp -> Choice f tps -> Bool
isChoice ix (Choice ix' _)
  | Just Refl <- ix `testEquality` ix' = True
  | otherwise = False

-- | Return the contents of a 'Choice' if its index matches, or a default value
-- otherwise. Analogous to 'Data.Either.fromLeft' and 'Data.Either.fromRight'.
fromChoice :: PL.Index tps tp -> f tp -> Choice f tps -> f tp
fromChoice ix a (Choice ix' b)
  | Just Refl <- ix `testEquality` ix' = b
  | otherwise = a

instance KnownRepr Proxy ctx where
  knownRepr = Proxy

-- | Type for the result of 'partitionChoices'.
data ChoiceList f tp = ChoiceList { unChoiceList :: [f tp] }

deriving instance Show (f tp) => Show (ChoiceList f tp)
instance (forall tp . Show (f tp)) => ShowF (ChoiceList f)

-- | Partition a list of 'Choice' into @n@ lists, where @n@ is the number of
-- different types in @tps@.
partitionChoices :: forall f tps . KnownRepr (PL.List Proxy) tps
                 => [Choice f tps]
                 -> PL.List (ChoiceList f) tps
partitionChoices [] = PL.imap (\_ _ -> ChoiceList []) proxies
  where proxies :: PL.List Proxy tps
        proxies = knownRepr
partitionChoices (Choice i a : cs) =
  let pRest = partitionChoices cs
  in PL.update pRest i (\(ChoiceList as) -> ChoiceList (a:as))

-- | 'slices' splits a list into @n@ pieces. The pieces are constructed by
-- taking every @n+k@th element of the list, where @k@ ranges from @0@ to @n-1@.
-- The last pieces will be shorter if @n@ does not divide the length of the
-- list. If @n <= 0@, @slices n l@ will return an error.
--
-- @
-- slices 3 [0..10] = [[0,3,6,9],[1,4,7,10],[2,5,8]]
-- @
--
-- @slices i@ is the @transpose@ of @chunksOf i@.
slices :: Int -> [a] -> [[a]]
slices i | i <= 0 = error "slices called on non-positive argument"
slices i = transpose . chunksOf i

-- | The inverse of 'slices'.
unSlices :: [[a]] -> [a]
unSlices = concat . transpose

-- | Average of a list of @Fractional a => a@.
avg :: Fractional a => [a] -> a
avg as = sum as / fromIntegral (length as)

-- | Generate all unique permutations of a list.
uniquePermutations :: Eq a => [a] -> [[a]]
uniquePermutations = nub . permutations

-- | Generate indices in preferred order.
--
-- TODO: Document this function better by explaining what "preferred order"
-- means, and come up with a better name for it.
indices :: Int
        -- ^ number of valid indices for each list
        -> Int
        -- ^ number of lists to index into
        -> [[Int]]
indices numRows numCols =
  -- Generate compositions in lexicographic order.
  let comps = reverse <$> compositions numRows numCols
  -- Map each composition to its list of unique permutations, and concatenate the result.
  in concatMap (uniquePermutations . concatMap (uncurry replicate) . flip zip [0..]) comps

-- | Like @sequence@ for a list of lists, but modify the order of the output by
-- using the /preferred order/.
sequencePreferred :: Int -> Int -> [[a]] -> [[a]]
sequencePreferred numRows numCols as =
  let ixss = indices numRows numCols
  in map (zipWith (!!) as) ixss

-- | Rotate a list by an 'Int', which can be negative, positive, or zero.
-- Negative 'Int's shift left, and positive 'Int's shift right.
rotate :: Int -> [a] -> [a]
rotate i as = take l . drop (i `mod` l) . cycle $ as
  where l = length as

-- | A distribution of @a@s is a occurrence map, assigning each @a@ to some
-- numeric type @b@.
type Distribution a b = Map.Map a b

-- | Create a simple 'Distribution' by counting occurrences.
getDist :: Ord a => [a] -> Distribution a Integer
getDist = foldr (flip (Map.insertWith (+)) 1) Map.empty

-- | A normalized 'Distribution', where the values are normalized to 'Float's
-- that add up to @1@.
type NDistribution a = Distribution a Float

-- | Compute a 'NDistribution' from an input list.
getNDist :: Ord a => [a] -> NDistribution a
getNDist as = fmap ((/ fromIntegral (length as)) . fromInteger) (getDist as)

-- | Average letter frequencies for English-language text, as given in
-- Katz/Lindell page 13, Figure 1.2.
englishDist :: NDistribution Alpha
englishDist = Map.fromList
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

-- | Given two distributions over the same type, get their index of coincidence.
-- Computes @Sum p_i*q_i@, where @i@ indexes the @a@ type, and @p_i@, @q_i@ are
-- the probabilities at @i@ of the two input distributions.
ioc :: Ord a => NDistribution a -> NDistribution a -> Float
ioc d1 d2 =
  let as = nub (Map.keys d1 ++ Map.keys d2)
  in sum $ map (\a -> Map.findWithDefault 0.0 a d1 * Map.findWithDefault 0.0 a d2) as

-- | The distance between two distributions based on the index of coincidence.
-- This works even if the keys of one of both of the distributions have been
-- permuted. This should be small if the second distribution is /encrypted
-- plaintext/, where the encryption is performed with a simple substitution
-- cipher, assuming the first is the probability distribution we'd expect from
-- plaintext.
d :: Ord a => NDistribution a -> NDistribution a -> Float
d dist1 dist2 = abs (dist1 `ioc` dist1 - dist2 `ioc` dist2)

-- | Computes the distance of the second distribution from the first. This
-- should be small if the second distribution is /decrypted plaintext/, assuming
-- the first is the probability distribution we'd expect from plaintext.
d' :: Ord a => NDistribution a -> NDistribution a -> Float
d' dist1 dist2 = abs (dist1 `ioc` dist1 - dist1 `ioc` dist2)

-- | An 'NgramCount' is just an occurrence count of lists of characters.
type NgramCount a = Distribution [a] Integer

-- | Given @n@ and a text, compute the probability distribution of all @n@-grams
-- in the text.
ngrams :: Ord a => Int -> [a] -> NgramCount a
ngrams n = getDist . mapMaybe (takeMaybe n) . tails

takeMaybe :: Int -> [a] -> Maybe [a]
takeMaybe n _ | n <= 0 = Just []
takeMaybe _ []         = Nothing
takeMaybe n (x:xs)     = (x:) <$> takeMaybe (n-1) xs

-- | Generate an 'NgramCount' from a file in the following format:
--
-- @
-- <ngram> <count>
-- <ngram> <count>
-- ...
-- @
--
-- where each <ngram> is a capitalized n-gram with alphabetical characters and
-- each <count> is a positive integer.
ngramsFromFile :: FilePath -> IO (NgramCount Alpha)
ngramsFromFile path = do
  lns <- lines <$> readFile path
  let f ln = let [ngramStr, countStr] = splitOn " " ln
             in (alphasFromString ngramStr, read countStr)
  return $ Map.fromList (map f lns)
