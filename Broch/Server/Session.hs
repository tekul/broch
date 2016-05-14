{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}
module Broch.Server.Session
    ( Session
    , LoadSession
    , SaveSession
    , defaultKey
    , defaultLoadSession
    , empty
    , lookup
    , delete
    , insert
    )
where

import Prelude hiding (lookup)
import Blaze.ByteString.Builder (toByteString)
import Control.Error
import Control.Monad.Trans (lift)
import Crypto.Random (getRandomBytes)
import qualified Data.Aeson as A
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.Int (Int64)
import qualified Data.List as L
import qualified Data.Map.Strict as M
import qualified Data.Serialize as S
import Data.Time.Clock.POSIX
import GHC.Generics (Generic)
import qualified Jose.Jwt as Jwt
import Jose.Jwa
import Jose.Jwk
import Network.HTTP.Types (Header, hCookie)
import Network.Wai (Request, requestHeaders)
import System.Directory (doesFileExist)
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

cookieEncoding :: Jwt.JwtEncoding
cookieEncoding = Jwt.JweEncoding A128KW A128GCM

defaultKeyFile :: FilePath
defaultKeyFile = "session_key.json"

-- TODO: Integrate session keys with KeyRing
defaultKey :: IO Jwk
defaultKey = getKey defaultKeyFile

getKey :: FilePath -> IO Jwk
getKey file = do
    exists <- doesFileExist file
    jwks   <- if exists
                  then A.decodeStrict <$> B.readFile file
                  else return Nothing
    case jwks of
        Just (JwkSet (k:_)) -> return k
        _ -> do
            k  <- getRandomBytes 16
            let jwk = SymmetricJwk k Nothing Nothing (Just (Encrypted A128KW))
            BL.writeFile file (A.encode (JwkSet [jwk]))
            return jwk

defaultLoadSession :: Int64 -> Jwk -> LoadSession
defaultLoadSession timeout key req = do
    now <- fmap round getPOSIXTime
    sessionCookie <- decodeCookie
    let session = case sessionCookie of
            Just (SessionCookie x s) -> if x < now then Nothing else Just s
            Nothing -> Nothing
    return (session, saveSesh now (isJust encryptedCookie))
  where
    encryptedCookie = do
        cookies <- L.lookup hCookie $ requestHeaders req
        L.lookup seshId (parseCookies cookies)
    decodeCookie = runMaybeT $ do
        ec <- hoistMaybe encryptedCookie
        cookie <- lift (Jwt.decode [key] (Just cookieEncoding) ec)
        case cookie of
            Right (Jwt.Jwe (_, content)) -> hoistMaybe . hush . S.decode $ content
            _ -> nothing

    seshId  = "bsid"

    -- Save session logic needs deal with:
    -- 1. If no cookie and no session then do nothing
    -- 2. Clearing the cookie if it existed at the start of the request but the session
    -- at the end is Nothing. This could be because
    --    a) The session was expired and was thus set to Nothing above, or
    --    b) The session was invalidated and set to Nothing during the request
    -- 3. Saving a session which exists at the end of the request
    saveSesh _ False Nothing = return Nothing
    saveSesh _ True Nothing  = return clearCookie
    saveSesh now _ (Just s) = do
        encoded <- Jwt.encode [key] cookieEncoding $ Jwt.Claims (S.encode $ SessionCookie (now + timeout) s)
        -- TODO: If this fails, it's a config error, so report it
        return $ case encoded of
            Right (Jwt.Jwt v) -> setCookieHeader $ makeCookie seshId v
            Left _            -> clearCookie

    clearCookie = setCookieHeader $ (makeCookie seshId "") { setCookieMaxAge = Just 0 }
    setCookieHeader cookie = Just ("Set-Cookie", toByteString $ renderSetCookie cookie)

    makeCookie n v = Cookie.def {
          setCookieName     = n
        , setCookieValue    = v
        , setCookieHttpOnly = True
        --, setCookieSecure   = True
        , setCookiePath     = Just "/"
        }
