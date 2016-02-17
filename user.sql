

CREATE TABLE op_user (
     id text PRIMARY KEY,
     username text NOT NULL UNIQUE CHECK (length(username) > 0),
     password text NOT NULL CHECK (length(password) > 0),
     otp_key text
);

CREATE TABLE user_info (
    id text PRIMARY KEY REFERENCES op_user,
    name text,
    given_name text,
    family_name text,
    middle_name text,
    nickname text,
    preferred_username text,
    profile text,
    picture text,
    website text,
    email text NOT NULL,
    email_verified boolean DEFAULT FALSE,
    gender text,
    birthdate date,
    zoneinfo text,
    locale text,
    phone_number text,
    phone_number_verified boolean DEFAULT FALSE,
    formatted text,
    street_address text,
    locality text,
    region text,
    postal_code text,
    country text,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE EXTENSION pgcrypto;

INSERT INTO op_user VALUES ('1234_cat_id', 'cat', crypt('cat', gen_salt('bf')), NULL);
Insert INTO user_info VALUES ('1234_cat_id', 'Catherine De Feline', 'Catherine', 'De Feline', 'Kitty', 'Cat', 'cat', 'http://placeholder', 'http://placeholder', 'http://placeholder', 'cat@connect.broch.io', FALSE, 'female', '1985-7-23', 'Europe/Paris', 'fr-FR', '+33 12 34 56 78', FALSE, '25 Cat Street, PussyVille, 1234567, Felineshire, France', '25 Cat Street', 'PussyVille', 'Felineshire', '1234567', 'FR');
