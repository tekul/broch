{-# LANGUAGE OverloadedStrings, QuasiQuotes, RecordWildCards #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Broch.PostgreSQL
where

import           Control.Monad (void)
import           Control.Monad.IO.Class
import           Data.Aeson
import           Data.ByteString (ByteString)
import           Data.Pool
import           Data.Text (Text)
import qualified Data.Text as T
import           Data.Text.Encoding (decodeUtf8, encodeUtf8)
import           Data.Time.Clock.POSIX
import           Data.Time.Format
import           Database.PostgreSQL.Simple
import           Database.PostgreSQL.Simple.FromField
import           Database.PostgreSQL.Simple.FromRow
import           Database.PostgreSQL.Simple.SqlQQ
import           Database.PostgreSQL.Simple.Types
import           Database.PostgreSQL.Simple.Time
import           Jose.Jwa (JwsAlg(..))
import           Jose.Jwt (IntDate (..))
import           Jose.Jwk

import           Broch.Model as M
import           Broch.Server.Config


postgreSQLBackend :: (MonadIO m, M.Subject s) => Pool Connection -> Config m s -> Config m s
postgreSQLBackend pool config = config
    { getClient = liftIO . loadClient pool
    , createClient = liftIO . insertClient pool
    , createAuthorization = \code usr clnt now scp n uri -> liftIO (insertAuthorization pool code usr clnt now scp n uri)
    , getAuthorization = liftIO . loadAndDeleteAuthorization pool
    , createApproval = liftIO . insertApproval pool
    , getApproval = \uid clnt now -> liftIO $ withResource pool (\conn -> loadApproval conn uid (clientId clnt) now)
    , getUserInfo = \uid clnt -> liftIO (loadUserInfo pool uid clnt)
    }

instance FromField ClientAuthMethod where
    fromField f Nothing = returnError UnexpectedNull f ""
    fromField f (Just v) = do
        -- TODO: Check type info
        let nm = decodeUtf8 v
        case lookupClientAuth nm of
            Nothing -> returnError ConversionFailed f "Unknown client auth"
            (Just cam) -> return cam

instance FromField GrantType where
    fromField f Nothing = returnError UnexpectedNull f ""
    fromField f v = do
        nm <- fromField f v
        case lookupGrantType nm of
            Nothing -> returnError ConversionFailed f "Unknown grant type"
            (Just g) -> return g

instance FromField Scope where
    fromField f Nothing = returnError UnexpectedNull f ""
    fromField f v = do
        nm <- fromField f v
        return (scopeFromName nm)

instance FromField JwsAlg where
    fromField f Nothing = returnError UnexpectedNull f ""
    fromField f v = do
        nm <- fromField f v
        case lookupJwsAlg nm of
            Nothing -> returnError ConversionFailed f "Unknown JWS algorithm"
            (Just a) -> return a

instance FromField AlgPrefs where
    fromField = fromJSONField

instance FromRow Client where
    fromRow = Client <$> field <*> field <*> (fromPGArray <$> field) <*> fmap fromPGArray field <*> field <*> field <*> (fromPGArray <$> field) <*> field <*> field <*> field <*> field <*> fieldWith fromJSONField <*> field <*> field <*> field <*> field

instance FromRow UserInfo where
    fromRow = UserInfo <$> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> field <*> parseBirthDate <*> field <*> field <*> field <*> field <*> parseAddress <*> parseIntDate

parseAddress :: RowParser (Maybe AddressClaims)
parseAddress = do
    r <- fromRow
    return $ case r of
        (Nothing, Nothing, Nothing, Nothing, Nothing, Nothing) -> Nothing
        (fmt, street, loc, reg, post, ctry) -> Just (AddressClaims fmt street loc reg post ctry)


parseKeys :: RowParser (Maybe [Jwk])
parseKeys = fieldWith fromJSONField

parseBirthDate :: RowParser (Maybe Text)
parseBirthDate = do
    dt <- field :: RowParser Date
    return $ case dt of
        Finite d -> Just . T.pack $ formatTime defaultTimeLocale (iso8601DateFormat Nothing) d
        _ -> Nothing

parseIntDate :: RowParser (Maybe IntDate)
parseIntDate = do
    t <- field
    return $ case t of
        Finite utc -> let intTime = utcTimeToPOSIXSeconds utc
                       in Just (IntDate intTime)
        _ -> Nothing

insertAuthorization :: M.Subject s
    => Pool Connection
    -> Text
    -> s
    -> M.Client
    -> POSIXTime
    -> [M.Scope]
    -> Maybe Text
    -> Maybe Text
    -> IO ()
insertAuthorization pool code user client now scope nonce mURI = withResource pool $ \conn ->
    void $ execute conn "insert into authz_code (code, uid, client_id, issued_at, scope, nonce, uri, auth_time) values (?,?,?,?,?,?,?,?)" (code, M.subjectId user, M.clientId client, posixSecondsToUTCTime now, PGArray (map M.scopeName scope), nonce, mURI, posixSecondsToUTCTime (M.authTime user))

loadAndDeleteAuthorization :: Pool Connection -> Text -> IO (Maybe Authorization)
loadAndDeleteAuthorization pool code = withResource pool $ \conn -> do
    as <- query conn [sql|
        DELETE FROM authz_code
        WHERE code = ?
        RETURNING uid, client_id, issued_at, scope, nonce, uri, auth_time |] [code]
    return $ case as of
        [(uid, cid, iat, PGArray scp, nonce, uri, autht)] -> Just (Authorization uid cid (IntDate (utcTimeToPOSIXSeconds iat)) (map M.scopeFromName scp) nonce uri (utcTimeToPOSIXSeconds autht))
        _ -> Nothing

insertApproval :: Pool Connection -> M.Approval -> IO ()
insertApproval pool (M.Approval uid cid scope denied (IntDate expires)) = withResource pool $ \conn ->
    void $ execute conn [sql|
        INSERT INTO authz_approval (uid, client_id, scope, denied_scope, expires_at)
        VALUES (?,?,?,?,?)
        ON CONFLICT (uid, client_id) DO UPDATE SET scope = EXCLUDED.scope, denied_scope = EXCLUDED.denied_scope, expires_at = EXCLUDED.expires_at
        |]
        (uid, cid, PGArray (map M.scopeName scope), PGArray (map M.scopeName denied), posixSecondsToUTCTime expires)

loadApproval :: Connection -> SubjectId -> ClientId -> POSIXTime -> IO (Maybe Approval)
loadApproval conn uid cid now = do
    as <- query conn [sql|
        SELECT scope, denied_scope, expires_at
        FROM authz_approval
        WHERE uid = ? AND client_id = ? AND expires_at > ?
        ORDER BY expires_at DESC |]
        (uid, cid, posixSecondsToUTCTime now)
    return $ case filter notExpired as of
        [(PGArray scope, PGArray denied, expires)] -> Just (Approval uid cid (map scopeFromName scope) (map scopeFromName denied) (IntDate (utcTimeToPOSIXSeconds expires)))
        _ -> Nothing
  where
    notExpired (_, _, t) = t > posixSecondsToUTCTime now

deleteApproval :: Connection -> SubjectId -> ClientId -> IO ()
deleteApproval conn uid cid =
    void $ execute conn [sql|
        DELETE FROM authz_approval
        where uid = ? and client_id = ? |] (uid, cid)


jwsAlgName :: JwsAlg -> Text
jwsAlgName a = case a of
    None  -> "none"
    HS256 -> "HS256"
    HS384 -> "HS384"
    HS512 -> "HS512"
    RS256 -> "RS256"
    RS384 -> "RS384"
    RS512 -> "RS512"
    ES256 -> "ES256"
    ES384 -> "ES384"
    ES512 -> "ES512"

lookupJwsAlg :: Text -> Maybe JwsAlg
lookupJwsAlg nm = case nm of
    "none"  -> Just None
    "HS256" -> Just HS256
    "HS384" -> Just HS384
    "HS512" -> Just HS512
    "RS256" -> Just RS256
    "RS384" -> Just RS384
    "RS512" -> Just RS512
    "ES256" -> Just ES256
    "ES384" -> Just ES384
    "ES512" -> Just ES512
    _       -> Nothing

insertClient :: Pool Connection -> Client -> IO ()
insertClient pool Client{..} = withResource pool $ \conn ->
    void $ execute conn [sql|
        INSERT INTO oauth2_client (id, secret, redirect_uri, allowed_scope, authorized_grant_types, access_token_validity, refresh_token_validity, auth_method, auth_alg, keys_uri, keys, id_token_algs, user_info_algs, request_obj_algs, sector_identifier_uri)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) |]
        ((clientId, clientSecret, PGArray redirectURIs, PGArray (map scopeName allowedScope), PGArray (map grantTypeName authorizedGrantTypes), accessTokenValidity, refreshTokenValidity, clientAuthMethodName tokenEndpointAuthMethod, fmap jwsAlgName tokenEndpointAuthAlg, clientKeysUri) :. (fmap toJSON clientKeys, fmap toJSON idTokenAlgs, fmap toJSON userInfoAlgs, fmap toJSON requestObjAlgs, sectorIdentifierURI))

loadClient :: Pool Connection -> ClientId -> IO (Maybe Client)
loadClient pool cid = withResource pool $ \conn -> do
    cs <- query conn [sql|
        SELECT id, secret, authorized_grant_types, redirect_uri, access_token_validity, refresh_token_validity, allowed_scope, auto_approve, auth_method, auth_alg, keys_uri, keys, id_token_algs, user_info_algs, request_obj_algs, sector_identifier_uri
        FROM oauth2_client
        WHERE id = ? |] [cid]
    case cs of
        [c] -> return (Just c)
        _   -> return Nothing

loadUserInfo :: Pool Connection -> LoadUserInfo IO
loadUserInfo pool uid _ = withResource pool $ \conn -> do
    us <- query conn [sql|
        SELECT * FROM user_info WHERE id=? |] [uid]
    case us of
        [u] -> return (Just u)
        _   -> return Nothing

passwordAuthenticate :: Pool Connection -> (ByteString -> ByteString -> Bool) -> Text -> ByteString -> IO (Maybe SubjectId)
passwordAuthenticate pool validatePwd username password = withResource pool $ \conn -> do
    us <- query conn [sql|
        SELECT id, password
        FROM op_user
        WHERE username = ? |] [username]
    return $ case us of
       [(uid, encodedPwd)] -> if validatePwd password (encodeUtf8 encodedPwd)
                                  then Just uid
                                  else Nothing
       _ -> Nothing
