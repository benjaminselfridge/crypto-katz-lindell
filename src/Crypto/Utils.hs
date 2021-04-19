-- | Helper functions.
module Crypto.Utils
  ( slices
  , unSlices
  , avg
  , sequencePreferred
  ) where

import Data.List (transpose, permutations, nub)
import Data.List.Split (chunksOf)
import Math.Combinat.Compositions

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
