{-# LANGUAGE TypeFamilies, OverloadedStrings, FlexibleContexts,
    MultiParamTypeClasses, DeriveGeneric #-}

module Broch.Yesod.Handler.OpenID where

import           Data.Aeson
import           Yesod.Core.Handler (HandlerT)

import           Broch.Yesod.Class
import           Broch.OpenID.Discovery

getUserInfoR = undefined

getOpenIDConfigurationR :: OpenIDConnectServer site => HandlerT site IO Value
getOpenIDConfigurationR = return $ toJSON defaultOpenIDConfiguration

getJwksR :: OpenIDConnectServer site => HandlerT site IO Value
getJwksR = fmap toJSON keySet
