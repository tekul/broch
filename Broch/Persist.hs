{-# LANGUAGE QuasiQuotes, TypeFamilies, OverloadedStrings, GADTs,
             FlexibleContexts, MultiParamTypeClasses, TemplateHaskell,
             GeneralizedNewtypeDeriving #-}

module Broch.Persist
    ( migrateAll
    , createAuthorization
    , getAuthorizationByCode
    , createClient
    , getClientById
    )
where

import Control.Monad (void)
import Data.Maybe (fromJust)
import Database.Persist (insert, getBy, delete, Entity(..), PersistStore)
import Database.Persist.TH (share, sqlSettings, mkMigrate, mkPersist, persistLowerCase)

import Data.Text (Text)
import Data.Time.Clock.POSIX

import qualified Broch.Model as M

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
AuthCode
  code   Text
  uid    Text
  client Text
  issueAt Int
  scope  [Text]
  uri    Text Maybe
  UniqueCode code
  deriving Show

Client
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
    void $ insert $ AuthCode code userId (M.clientId client) (fromIntegral $ round now) scope mURI

getAuthorizationByCode code = do
    record <- getBy $ UniqueCode code
    case record of
        Nothing -> return Nothing
        Just (Entity key (AuthCode _ uid client issueAt scope uri)) -> do
            delete key
            return $ Just $ M.Authorization uid client (fromIntegral issueAt) scope uri

createClient (M.Client cid ms gs uris atv rtv scps appr roles) =
    void $ insert $ Client cid ms (map M.grantTypeName gs) uris atv rtv scps appr roles

getClientById cid = do
    record <- getBy $ UniqueClientId cid
    case record of
        Nothing -> return Nothing
        Just (Entity key (Client _ ms gs uris atv rtv scps appr roles)) -> do
            let grants = Prelude.map (\g -> fromJust $ lookup g M.grantTypes) gs
            return $ Just $ M.Client cid ms grants uris atv rtv scps appr roles
