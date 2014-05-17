{-# LANGUAGE ExistentialQuantification #-}

module Broch.Random
    ( randomBytes
    , withCPRG
    ) where

import Control.Monad (liftM)
import Crypto.Random (CPRG(..))
import Crypto.Random.AESCtr (AESRNG, makeSystem)
import Data.ByteString (ByteString)
import Data.IORef (IORef, atomicModifyIORef, newIORef)
import Data.Tuple (swap)
import System.IO.Unsafe (unsafePerformIO)

reseedAfter :: Int
reseedAfter = 1000000 -- Reseed after 1MB

newRNG :: IO AESRNG
newRNG = liftM (cprgSetReseedThreshold reseedAfter) makeSystem

rngRef :: IORef AESRNG
rngRef = unsafePerformIO $ newRNG >>= newIORef
{-# NOINLINE rngRef #-}

randomBytes :: Int -> IO ByteString
randomBytes n = do
    bs <- atomicModifyIORef rngRef $
        \rng -> swap $ cprgGenerate n rng
    return $! bs

withCPRG :: (AESRNG -> (b, AESRNG)) -> IO b
withCPRG f = do
    a <- atomicModifyIORef rngRef $
        \rng -> swap $ f rng
    return $! a

