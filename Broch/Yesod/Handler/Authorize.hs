{-# LANGUAGE TypeFamilies, OverloadedStrings, GADTs,
             FlexibleContexts, MultiParamTypeClasses,
             GeneralizedNewtypeDeriving #-}

module Broch.Yesod.Handler.Authorize
    ( getAuthorizeR
    )
where

import Yesod.Core
import Yesod.Auth

import Control.Monad.Error

import Data.List ((\\))
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock.POSIX
import Network.HTTP.Types
import qualified Data.Map as Map

import Broch.Yesod.Class
import Broch.Model
import Broch.OAuth2.Authorize


{-
  GET Request to the authorization endpoint.

  Used by authorization code and implicit grants.
-}
getAuthorizeR :: (OAuth2Server site, YesodAuth site, AuthId site ~ Text) => HandlerT site IO Html
getAuthorizeR = do
    user <- maybeAuthId >>= maybe redirectLogin return
    env  <- liftM (toMap . reqGetParams) getRequest
    now  <- liftIO getPOSIXTime

    either evilClientError (redirectWith status302) =<< processAuthorizationRequest getClient (liftIO generateCode) createAuthorization resourceOwnerApproval user env now

 where
    -- | Report a "bad client" error to the user without a redirect
    evilClientError :: EvilClientError -> HandlerT site IO a
    evilClientError = sendResponseStatus status400 . RepPlain . toContent . show

    resourceOwnerApproval uid client requestedScope now = do
        -- Try to load a previous approval
        maybeApproval <- getApproval uid client now
        case maybeApproval of
            -- TODO: Check scope overlap and allow asking for extra scope
            -- not previously granted
            Just (Approval _ _ scope _) -> return (scope \\ requestedScope)
            -- Nothing exists: Redirect to approval handler with scopes and client id
            Nothing -> redirectApproval (clientId client) requestedScope

redirectApproval :: OAuth2Server site => ClientId -> [Scope] -> HandlerT site IO a
redirectApproval cid scope = do
    setUltDestCurrent
    y <- getYesod
    let query = [("client_id", cid), ("scope", T.intercalate " " (map scopeName scope))] :: [(Text,Text)]
    redirect (approvalRoute y, query)


redirectLogin :: Yesod site => HandlerT site IO a
redirectLogin = do
    y <- getYesod
    setUltDestCurrent
    case authRoute y of
        Just z -> redirect z
        Nothing -> permissionDenied "Please configure authRoute"

toMap :: [(Text, a)] -> Map.Map Text [a]
toMap = Map.unionsWith (++) . map (\(x, y) -> Map.singleton x [y])