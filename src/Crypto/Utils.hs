-- | Helper functions.
module Crypto.Utils
  ( nths
  , avg
  ) where

import Data.List (transpose)
import Data.List.Split (chunksOf)

-- | 'nths' split a list into @n@ pieces. The pieces are constructed by taking
-- every @n+k@th element of the list, where @k@ ranges from @0@ to @n-1@. The
-- last pieces will be shorter if @n@ does not divide the length of the list. If
-- @n <= 0@, @nths n l@ will return an error.
--
-- @
-- nths 3 [0..10] = [[0,3,6,9],[1,4,7,10],[2,5,8]]
-- @
--
-- @nths i@ is the @transpose@ of @chunksOf i@.
nths :: Int -> [a] -> [[a]]
nths i | i <= 0 = error "nths called on non-positive argument"
nths i = transpose . chunksOf i

-- | Average of a list of @Fractional a => a@.
avg :: Fractional a => [a] -> a
avg as = sum as / fromIntegral (length as)
