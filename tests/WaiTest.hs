{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module WaiTest where

import qualified Blaze.ByteString.Builder as Builder
import Control.Arrow (second)
import Control.Monad (when, unless)
import Control.Monad.IO.Class (liftIO)
import qualified Control.Monad.Trans.State as ST
import Data.Aeson (encode, Result(..), fromJSON, eitherDecode', FromJSON, ToJSON)
import Data.Aeson.Types (Value(..))
import Data.ByteArray.Encoding
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.HashMap.Strict as H
import qualified Data.List as DL
import qualified Data.Map as M
import Data.Maybe (fromMaybe)
import qualified Data.Text.Encoding as TE
import Data.Text (Text)
import Data.Time.Clock (getCurrentTime)
import qualified Network.HTTP.Types as H
import Network.HTTP.Types.QueryLike
import Network.URI (URI, uriPath, uriQuery, uriFragment, parseURIReference)
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

getP :: ByteString -> [(Text, Text)] -> WaiTest ()
getP url params = request "" $ mkRequest "GET" $ B.concat [strippedUrl, H.renderQuery True $ toQuery params]
  where
    strippedUrl = if B.isPrefixOf "http" url
                      then B.dropWhile ('/' /=) $ B.drop 8 url
                      else url

post :: ByteString -> [(Text, Text)] -> WaiTest ()
post url params = let content = H.renderQuery False $ toQuery params
                  in request content $ addHeader ("Content-Type", "application/x-www-form-urlencoded") $ mkRequest "POST" url

postJSON :: ToJSON a => ByteString -> a -> WaiTest ()
postJSON url v = request (BL.toStrict $ encode v) $ addHeader ("Content-Type", "application/json") $ mkRequest "POST" url

dumpResponse = withResponse $ liftIO . print

statusIs expected = withResponse $ \SResponse { simpleStatus = s } ->
    liftIO $ HUnit.assertBool ("Expected status " ++ show expected ++ " but was " ++ show (H.statusCode s)) (expected == H.statusCode s)

statusIsGood = withResponse $ \SResponse { simpleStatus = s } -> do
    let sc = H.statusCode s
    liftIO $ HUnit.assertBool ("Expect 20x or 30x status but was " ++ show sc) (sc >= 200 && sc < 400)

followRedirect :: WaiTest ()
followRedirect = do
    Just response <- fmap testResponse ST.get
    unless (isRedirect response) dumpResponse
    liftIO $ HUnit.assertBool ("Expected a redirect but status was " ++ show (simpleStatus response)) (isRedirect response)
    getLocationHeader >>= get

isRedirect :: SResponse -> Bool
isRedirect r = let status = simpleStatus r
               in H.found302 == status || H.seeOther303 == status

failure msg = liftIO $ HUnit.assertFailure msg

basicAuth :: Text -> Text -> WaiTest ()
basicAuth name password = let authz = Just $ B.concat ["Basic ", convertToBase Base64 $ B.concat [TE.encodeUtf8 name, ":", TE.encodeUtf8 password]]
                          in  ST.modify $ \s -> s {testAuthz = authz}

bearerAuth :: ByteString -> WaiTest()
bearerAuth t = ST.modify $ \s -> s {testAuthz = Just $ B.concat ["Bearer ", t]}

clearAuthz :: WaiTest()
clearAuthz = ST.modify $ \s -> s {testAuthz = Nothing}

getLocationHeader :: WaiTest ByteString
getLocationHeader = withResponse $ \SResponse { simpleHeaders = h } ->
    case lookup "Location" h of
        Nothing -> fail "No location header found"
        Just l  -> return l

getLocationParam :: ByteString -> WaiTest Text
getLocationParam name = getLocationParams >>= \q ->
    case lookup name q of
        Nothing -> fail $ "Query parameter not found: " ++ B.unpack name
        Just p  -> return $ TE.decodeUtf8 p

getLocationParams :: WaiTest [(ByteString, ByteString)]
getLocationParams = do
    l <- getLocationURI
    let ps = case uriQuery l of
               [] -> uriFragment l
               _  -> uriQuery l
    return $ map (second $ fromMaybe "") $ H.parseQuery $ B.pack ps

getLocationURI :: WaiTest URI
getLocationURI = do
    l <- fmap B.unpack getLocationHeader
    case parseURIReference l of
        Nothing -> fail $ "Invalid redirect URI: " ++ l
        Just r  -> return r

withResponse :: (SResponse -> WaiTest a) -> WaiTest a
withResponse f = do
    Just response <- fmap testResponse ST.get
    f response


withOptionalRedirect :: String -> WaiTest () -> WaiTest ()
withOptionalRedirect path f = withResponse $ \r ->
    when (isRedirect r) $ do
        p <- fmap uriPath getLocationURI
        when (p == path) $ followRedirect >> statusIsGood >> f

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

jsonBody :: FromJSON a => WaiTest a
jsonBody = do
    jsn <- jsonContent
    case fromJSON jsn of
        Success a -> return a
        _         -> error "Failed to decode JSON"

jsonField :: Text -> WaiTest Text
jsonField name = do
    Object jsn <- jsonContent
    case H.lookup name jsn of
        Just (String v) -> return v
        _ -> dumpResponse >> error "Failed to find named string field in JSON content"

jsonContent :: WaiTest Value
jsonContent = do
    jsn <- withResponse $ return . simpleBody
    case eitherDecode' jsn of
        Left e -> error $ "Failed to decode response body as JSON " ++ show e
        Right a -> return a

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

assertEqual :: (Show a, Eq a) => String -> a -> a -> WaiTest ()
assertEqual msg a b = liftIO $ HUnit.assertBool (msg ++ ": " ++ show a ++ " /= " ++ show b) (a == b)
