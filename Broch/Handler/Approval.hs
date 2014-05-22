{-# LANGUAGE TypeFamilies, OverloadedStrings, GADTs,
             FlexibleContexts, MultiParamTypeClasses,
             GeneralizedNewtypeDeriving, QuasiQuotes #-}

module Broch.Handler.Approval
    ( getApprovalR
    , postApprovalR
    )
where

import Control.Applicative
import Data.Text (Text)
import Data.Text.Read (decimal, Reader)
import Data.Time.Clock.POSIX
import Data.Int (Int64)
import qualified Data.Text as T
import Yesod.Auth
import Yesod.Core
import Yesod.Form
import Yesod.Form.Fields

import Broch.Handler.Authorize
import Broch.Class
import Broch.Model


getApprovalR :: (YesodAuth site, YesodOAuth2Server site) => HandlerT site IO Html
getApprovalR = do
    site <- getYesod
    Just uid <- maybeAuthId
    Just clntId <- lookupGetParam "client_id"
    Just scope  <- lookupGetParam "scope" >>= \ms -> return $ fmap (T.splitOn " ") ms
    posixTime   <- liftIO $ getPOSIXTime
    let now = round $ posixTime :: Int64
    let oneDay  = now + aDay
    let oneWeek = now + 7*aDay
    let oneMonth = now + 30*aDay
    defaultLayout $ do
        setTitle "Authorization Approvals page"
        [whamlet|
<h2>Authorization Approval Request
<p>Client #{clntId} is requesting access:

<form method=post action=@{approvalRoute site} >
    <input type="hidden" name="client_id" value="#{clntId}">
    <label for="expiry">Expires after
    <select name="expiry">
        <option value="#{oneDay}">One day
        <option value="#{oneWeek}">One week
        <option value="#{oneMonth}">30 Days
    $forall s <- scope
       <input type="checkbox" name="scope" value="#{s}">#{s}
    <br>
    <button>Grant Access
|]
  where
    aDay = round posixDayLength :: Int64

postApprovalR :: (YesodAuth site, YesodOAuth2Server site, AuthId site ~ Text) => HandlerT site IO Html
postApprovalR = do
    site <- getYesod
    Just uid <- maybeAuthId
    Just clntId <- lookupPostParam "client_id"
    Just expiryTxt <- lookupPostParam "expiry"
    scope <- lookupPostParams "scope"
    let Right (expiry, _) = decimal expiryTxt
    liftIO $ saveApproval site $ Approval uid clntId scope (fromIntegral (expiry :: Int64))
    redirectUltDest ("/" :: Text)

