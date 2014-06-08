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
    )
where

import Control.Monad (void)
import Data.Maybe (fromJust)
import Database.Persist (insert, getBy, delete, deleteBy, Entity(..))
import Database.Persist.TH (share, sqlSettings, mkMigrate, mkPersist, persistLowerCase)

import Data.Text (Text)
import Data.Time.Clock.POSIX
import Data.Time.Clock

import qualified Broch.Model as M

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
AuthCode sql=authz_code
  code   Text
  uid    Text
  clientId Text
  issuedAt UTCTime
  scope  [Text]
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
  roles          [Text]
  UniqueClientId clientId
  deriving Show
|]


createAuthorization code userId client now scope mURI =
    void $ insert $ AuthCode code userId (M.clientId client) (posixSecondsToUTCTime now) (map M.scopeName scope) mURI

getAuthorizationByCode code = do
    record <- getBy $ UniqueCode code
    case record of
        Nothing -> return Nothing
        Just (Entity key (AuthCode _ uid client issuedAt scope uri)) -> do
            delete key
            return $ Just $ M.Authorization uid client (M.TokenTime $ utcTimeToPOSIXSeconds issuedAt) (map M.scopeFromName scope) uri

createApproval (M.Approval uid clientId scope (M.TokenTime expires)) =
    void $ insert $ Approval uid clientId (map M.scopeName scope) (posixSecondsToUTCTime expires)

-- getApproval :: PersistUnique m => Text -> Text -> POSIXTime -> m (Maybe M.Approval)
getApproval uid cid now = do
    record <- getBy $ UniqueApproval uid cid
    case record of
        Nothing -> return Nothing
        Just (Entity key (Approval _ _ scope expiry)) -> do
            let posixExpiry = utcTimeToPOSIXSeconds expiry
            if now > posixExpiry
                then delete key >> return Nothing
                else return $ Just $ M.Approval uid cid (map M.scopeFromName scope) (M.TokenTime posixExpiry)

deleteApproval uid cid = deleteBy $ UniqueApproval uid cid

createClient (M.Client cid ms gs uris atv rtv scps appr roles) =
    void $ insert $ Client cid ms (map M.grantTypeName gs) uris atv rtv (map M.scopeName scps) appr roles

getClientById cid = do
    record <- getBy $ UniqueClientId cid
    case record of
        Nothing -> return Nothing
        Just (Entity key (Client _ ms gs uris atv rtv scps appr roles)) -> do
            let grants = Prelude.map (\g -> fromJust $ lookup g M.grantTypes) gs
            return $ Just $ M.Client cid ms grants uris atv rtv (map M.scopeFromName scps) appr roles
