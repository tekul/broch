{-# LANGUAGE QuasiQuotes, TypeFamilies, OverloadedStrings, GADTs,
             FlexibleContexts, MultiParamTypeClasses, TemplateHaskell,
             GeneralizedNewtypeDeriving #-}

module Broch.Persist
    ( migrateAll
    , createAuthorization
    , getAuthorizationByCode
    , createClient
    , getClientById
    , createApproval
    , getApproval
    , createUser
    , getUserById
    , getUserByUsername
    )
where

import           Control.Monad (void)
import           Data.Aeson (encode, decodeStrict)
import           Data.ByteString.Lazy (toStrict)
import           Data.Maybe (fromJust)
import           Database.Persist (PersistUnique, PersistStore, insert, getBy, delete, deleteBy, Entity(..))
import           Database.Persist.TH (share, sqlSettings, mkMigrate, mkPersist, persistLowerCase)

import           Data.Text (Text)
import qualified Data.Text.Encoding as TE
import           Data.Time.Clock.POSIX
import           Data.Time.Clock
import           Jose.Jwt (IntDate (..))

import qualified Broch.Model as M
import           Broch.Scim

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
AuthCode sql=authz_code
  code   Text
  uid    Text
  clientId Text
  issuedAt UTCTime
  scope  [Text]
  nonce  Text Maybe
  uri    Text Maybe
  UniqueCode code
  deriving Show

Approval sql=authz_approval
  uid      Text
  clientId Text
  scope    [Text]
  expiresAt UTCTime
  UniqueApproval uid clientId
  deriving Show

Client sql=oauth2_client
  clientId       Text
  clientSecret   Text Maybe
  authorizedGrantTypes [Text]
  redirectURIs   [Text]
  accessTokenValidity Int
  refreshTokenValidity Int
  allowedScope   [Text]
  autoapprove    Bool
  UniqueClientId clientId
  deriving Show

User
  uid            Text
  username       Text
  password       Text
  scim           Text
  UniqueUserId   uid
  UniqueUserName username
  deriving Show
|]

createAuthorization :: (PersistStore m, Functor m)
                    => Text
                    -> Text
                    -> M.Client
                    -> POSIXTime
                    -> [M.Scope]
                    -> Maybe Text
                    -> Maybe Text
                    -> m ()
createAuthorization code userId client now scope nonce mURI =
    void $ insert $ AuthCode code userId (M.clientId client) (posixSecondsToUTCTime now) (map M.scopeName scope) nonce mURI

getAuthorizationByCode :: (PersistUnique m, Functor m)
                       => Text
                       -> m (Maybe M.Authorization)
getAuthorizationByCode code = do
    record <- getBy $ UniqueCode code
    case record of
        Nothing -> return Nothing
        Just (Entity key (AuthCode _ uid client issuedAt scope nonce uri)) -> do
            delete key
            return $ Just $ M.Authorization uid client (IntDate $ utcTimeToPOSIXSeconds issuedAt) (map M.scopeFromName scope) nonce uri

createApproval :: (PersistStore m, Functor m)
               => M.Approval
               -> m ()
createApproval (M.Approval uid clientId scope (IntDate expires)) =
    void $ insert $ Approval uid clientId (map M.scopeName scope) (posixSecondsToUTCTime expires)

getApproval :: PersistUnique m
            => Text
            -> Text
            -> POSIXTime
            -> m (Maybe M.Approval)
getApproval uid cid now = do
    record <- getBy $ UniqueApproval uid cid
    case record of
        Nothing -> return Nothing
        Just (Entity key (Approval _ _ scope expiry)) -> do
            let posixExpiry = utcTimeToPOSIXSeconds expiry
            if now > posixExpiry
                then delete key >> return Nothing
                else return $ Just $ M.Approval uid cid (map M.scopeFromName scope) (IntDate posixExpiry)

deleteApproval :: PersistUnique m
               => Text
               -> Text
               -> m ()
deleteApproval uid cid = deleteBy $ UniqueApproval uid cid

createClient :: (PersistStore m, Functor m)
             => M.Client
             -> m ()
createClient (M.Client cid ms gs uris atv rtv scps appr) =
    void $ insert $ Client cid ms (map M.grantTypeName gs) uris atv rtv (map M.scopeName scps) appr

getClientById :: PersistUnique m
              => Text
              -> m (Maybe M.Client)
getClientById cid = do
    record <- getBy $ UniqueClientId cid
    case record of
        Nothing -> return Nothing
        Just (Entity _ (Client _ ms gs uris atv rtv scps appr)) -> do
            let grants = Prelude.map (\g -> fromJust $ lookup g M.grantTypes) gs
            return $ Just $ M.Client cid ms grants uris atv rtv (map M.scopeFromName scps) appr

createUser :: (PersistStore m, Functor m)
           => Text
           -> Text
           -> ScimUser
           -> m ()
createUser uid pass scimUser =
    void $ insert $ User uid (scimUserName scimUser) pass $ TE.decodeUtf8 $ toStrict $ encode scimUser

getUserById :: PersistUnique m
            => M.SubjectId
            -> m (Maybe ScimUser)
getUserById uid = do
    record <- getBy $ UniqueUserId uid
    case record of
        Nothing -> return Nothing
        Just (Entity _ (User _ _ _ scim)) -> return $ decodeStrict $ TE.encodeUtf8 scim

getUserByUsername :: PersistUnique m
                  => Text
                  -> m (Maybe (M.SubjectId, Text))
getUserByUsername name = do
    record <- getBy $ UniqueUserName name
    case record of
        Nothing -> return Nothing
        Just (Entity _ (User uid _ password _)) -> return $ Just (uid, password)


