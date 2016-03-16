
CREATE TYPE client_auth_method AS ENUM ('client_secret_post', 'client_secret_basic', 'client_secret_jwt', 'private_key_jwt', 'none');

CREATE TABLE oauth2_client (
    id text PRIMARY KEY,
    secret text,
    authorized_grant_types text[],
    redirect_uri text[],
    access_token_validity integer NOT NULL,
    refresh_token_validity integer NOT NULL,
    allowed_scope text[],
    auto_approve boolean DEFAULT FALSE,
    auth_method client_auth_method NOT NULL,
    auth_alg text,
    keys_uri text,
    keys jsonb,
    id_token_algs jsonb,
    user_info_algs jsonb,
    request_obj_algs jsonb,
    sector_identifier text NOT NULL
);

CREATE TABLE authz_code (
    code text PRIMARY KEY,
    uid  text NOT NULL,
    client_id text NOT NULL REFERENCES oauth2_client,
    issued_at timestamptz NOT NULL,
    scope text[] NOT NULL,
    nonce text NULL,
    uri   text NULL,
    auth_time timestamptz NOT NULL
);

CREATE TABLE authz_approval (
    uid text,
    client_id text REFERENCES oauth2_client,
    scope text[] NOT NULL,
    denied_scope text[] NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (uid, client_id)
);

insert into oauth2_client values ('app', 'appsecret', '{"authorization_code"}', '{"http://localhost:8080/app"}', 3600, 7200, '{"openid","profile","address","email"}', false, 'client_secret_basic', null, null, '[]', null, null, null, 'localhost');
