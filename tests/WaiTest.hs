{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module WaiTest where

import qualified Blaze.ByteString.Builder as Builder
import Control.Arrow (second)
import Control.Monad (liftM)
import Control.Monad.IO.Class (liftIO)
import qualified Control.Monad.Trans.State as ST
import Data.Aeson (encode, ToJSON)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.List as DL
import qualified Data.Map as M
import Data.Maybe (fromMaybe)
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (getCurrentTime)
import qualified Network.HTTP.Types as H
import Network.HTTP.Types.QueryLike
import Network.URI (URI, uriQuery, parseURIReference)
import Network.Wai
import Network.Wai.Internal
import Network.Wai.Test hiding (request)
import qualified Test.HUnit as HUnit
import qualified Web.Cookie as C

-- This code is influenced by yesod-test, but for plain Wai requests.
-- The wai-test module by itself only supports simple request testing,
-- so this adds cookie handling and access to the previous response.

type Cookies = M.Map ByteString C.SetCookie

data TestState = TestState
    { testApp      :: !Application
    , testCookies  :: !Cookies
    , testAuthz    :: !(Maybe ByteString)
    , testResponse :: !(Maybe SResponse)
    }

type WaiTest = ST.StateT TestState IO

runTest :: Application -> WaiTest a -> IO a
runTest a t = ST.evalStateT t $ TestState a M.empty Nothing Nothing

reset :: WaiTest ()
reset = do
    TestState app _ _ _ <- ST.get
    ST.put $ TestState app M.empty Nothing Nothing

get :: ByteString -> WaiTest ()
get url = getP url []

getP :: ByteString -> [(ByteString, ByteString)] -> WaiTest ()
getP url params = request "" $ mkRequest "GET" $ B.concat [strippedUrl, H.renderQuery True $ toQuery params]
  where
    strippedUrl = if B.isPrefixOf "http" url
                      then B.dropWhile ('/' /=) $ B.drop 8 url
                      else url

post :: ByteString -> [(ByteString, ByteString)] -> WaiTest ()
post url params = let content = H.renderQuery False $ toQuery params
                  in request content $ addHeader ("Content-Type", "application/x-www-form-urlencoded") $ mkRequest "POST" url

postJSON :: ToJSON a => ByteString -> a -> WaiTest ()
postJSON url v = request (BL.toStrict $ encode v) $ addHeader ("Content-Type", "application/json") $ mkRequest "POST" url

dumpResponse = withResponse $ liftIO . print

statusIs expected = withResponse $ \SResponse { simpleStatus = s } ->
    liftIO $ HUnit.assertBool ("Expected status " ++ show expected ++ " but was " ++ show (H.statusCode s)) (expected == H.statusCode s)

failure msg = liftIO $ HUnit.assertFailure msg

basicAuth name password = do
    s <- ST.get
    let authz = B.concat ["Basic ", B64.encode $ B.concat [name, ":", password]]
    ST.put s {testAuthz = Just authz}

getLocationHeader :: WaiTest ByteString
getLocationHeader = withResponse $ \SResponse { simpleHeaders = h } ->
    case lookup "Location" h of
        Nothing -> fail "No location header found"
        Just l  -> return l

getLocationParam :: ByteString -> WaiTest ByteString
getLocationParam name = getLocationQuery >>= \q ->
    case lookup name q of
        Nothing -> fail $ "Query parameter not found: " ++ B.unpack name
        Just p  -> return p

getLocationQuery :: WaiTest [(ByteString, ByteString)]
getLocationQuery = do
    l <- getLocationURI
    return $ map (second $ fromMaybe "") $ H.parseQuery $ (B.pack . uriQuery) l

getLocationURI :: WaiTest URI
getLocationURI = do
    l <- liftM B.unpack getLocationHeader
    case parseURIReference l of
        Nothing -> fail $ "Invalid redirect URI: " ++ l
        Just r  -> return r

withResponse :: (SResponse -> WaiTest a) -> WaiTest a
withResponse f = do
    Just response <- fmap testResponse ST.get
    f response

mkRequest method url =
    let (urlPath, urlQuery) = parseUrl
        rawPath = B.concat ["/", B.intercalate "/" urlPath]
    in defaultRequest
        { requestMethod = method
        , rawPathInfo = rawPath
        , pathInfo = map TE.decodeUtf8 urlPath
        , queryString = urlQuery
        , rawQueryString = H.renderQuery True urlQuery
        }
  where
    parseUrl = let (p, q) = B.break (== '?') url
                   urlPath = case DL.filter (/="") $ B.split '/' p of
                       ("http:":_:rest) -> rest
                       ("https:":_:rest) -> rest
                       x -> x
               in (urlPath, H.parseQuery q)

request content req = do
    TestState app oldCookies authz _ <- ST.get
    now <- liftIO getCurrentTime
    let cookies = M.filter (notExpired now) oldCookies

    response <- liftIO $ flip runSession app $ srequest SRequest
        { simpleRequest = addContentLength $ addAuthz authz $ addCookies cookies req
        , simpleRequestBody = BL.fromStrict content
        }

    let newCookies = map (C.parseSetCookie . snd) $ DL.filter (("Set-Cookie"==) . fst) $ simpleHeaders response
        cookies' = M.fromList [(C.setCookieName c, c) | c <- newCookies] `M.union` cookies

    ST.put $ TestState app cookies' authz (Just response)
  where
    addAuthz Nothing  r = r
    addAuthz (Just a) r = addHeader ("Authorization", a) r
    addContentLength    = addHeader ("Content-Length", B.pack $ show $ B.length content)
    addCookies cookies r@Request { rawPathInfo = path } = addHeader ("Cookie", cookieHeader) r
      where
        cookieHeader = Builder.toByteString . C.renderCookies $
            [(C.setCookieName c, C.setCookieValue c) | c <- map snd $ M.toList cookies, isValidPath path c]

    notExpired t c = maybe True (< t) $ C.setCookieExpires c

    isValidPath p c = maybe True (`B.isPrefixOf` p) $ C.setCookiePath c

addHeader hdr r@Request { requestHeaders = hs } = r { requestHeaders = hdr : hs }

assertEqual :: (Eq a) => String -> a -> a -> WaiTest ()
assertEqual msg a b = liftIO $ HUnit.assertBool msg (a == b)

