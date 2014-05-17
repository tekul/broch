module Broch.Handler.Class

where

import Yesod.Core.Handler (HandlerT)
import Data.Text
import Data.Time.Clock.POSIX (POSIXTime)
import Data.ByteString (ByteString)
import Broch.Model


class OAuth2Server site where
    getClient :: ClientId -> HandlerT site IO (Maybe Client)

    createAuthorization :: Text
                        -> OAuth2User
                        -> Client
                        -> POSIXTime
                        -> [Text]
                        -> Maybe Text
                        -> HandlerT site IO ()

    authenticateResourceOwner :: Text
                              -> Text
                              -> HandlerT site IO (Maybe OAuth2User)

    getAuthorization :: Text
                     -> HandlerT site IO (Maybe Authorization)

    createAccessToken :: Maybe OAuth2User   -- ^ The end user (resource owner)
                      -> Client             -- ^ The OAuth client the token will be issued to
                      -> GrantType          -- ^ The grant type under which the token was requested
                      -> [Text]             -- ^ The scope granted to the client
                      -> POSIXTime          -- ^ Current time
                      -> HandlerT site IO (ByteString, Maybe ByteString, TokenTTL)

    decodeRefreshToken :: Client
                       -> Text          -- ^ Refresh token parameter
                       -> HandlerT site IO (Maybe AccessGrant)
