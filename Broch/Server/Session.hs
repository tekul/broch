{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}
module Broch.Server.Session
    ( Session
    , LoadSession
    , SaveSession
    , defaultLoadSession
    , empty
    , lookup
    , delete
    , insert
    )
where

import Debug.Trace

import Prelude hiding (lookup)
import Blaze.ByteString.Builder (toByteString)
import Control.Error
import Data.ByteString (ByteString)
import Data.Int (Int64)
import qualified Data.List as L
import qualified Data.Map.Strict as M
import qualified Data.Serialize as S
import Data.Time.Clock.POSIX
import GHC.Generics (Generic)
import Network.HTTP.Types (Header, hCookie)
import Network.Wai (Request, requestHeaders)
import qualified Web.ClientSession as CS
import Web.Cookie as Cookie

data SessionCookie = SessionCookie Int64 Session deriving (Generic, Show)
newtype Session = Session (M.Map ByteString ByteString) deriving (Generic, Show)
instance S.Serialize Session

instance S.Serialize SessionCookie
type LoadSession = Request -> IO (Maybe Session, SaveSession)
type SaveSession = Maybe Session -> IO (Maybe Header)

empty :: Session
empty = Session M.empty

insert :: Session -> ByteString -> ByteString -> Session
insert (Session m) k v = Session $ M.insert k v m

lookup :: Session -> ByteString -> Maybe ByteString
lookup (Session m) k = M.lookup k m

delete :: Session -> ByteString -> Session
delete (Session m) k = Session $ M.delete k m

defaultLoadSession :: Int64 -> CS.Key -> LoadSession
defaultLoadSession timeout key req = do
    now <- fmap round getPOSIXTime
    let (session, expired) = case trace (show sessionCookie) sessionCookie of
                                Just (SessionCookie x s) -> if x < now
                                                                then (Nothing, True)
                                                                else (Just s, False)
                                Nothing -> (Nothing, False)
    return (session, saveSesh now expired)
  where
    seshId  = "bsid"
    sessionCookie = hush . S.decode =<< CS.decrypt key =<< L.lookup seshId cookies

    cookies = maybe [] parseCookies $ L.lookup hCookie $ requestHeaders req

    saveSesh _ False Nothing = return Nothing
    saveSesh _ True Nothing  = return clearCookie
    saveSesh now _ (Just s) = do
        value <- CS.encryptIO key $ S.encode $ SessionCookie (now + timeout) s
        return . setCookieHeader $ makeCookie seshId value

    clearCookie = setCookieHeader $ (makeCookie seshId "") { setCookieMaxAge = Just 0 }
    setCookieHeader cookie = Just ("Set-Cookie", toByteString $ renderSetCookie cookie)

    makeCookie n v = Cookie.def {
          setCookieName     = n
        , setCookieValue    = v
        , setCookieHttpOnly = True
        --, setCookieSecure   = True
        , setCookiePath     = Just "/"
        }

