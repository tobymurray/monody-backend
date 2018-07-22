DROP DATABASE IF EXISTS auth;
DROP ROLE IF EXISTS auth_anonymous;
DROP ROLE IF EXISTS auth_authenticated;
DROP ROLE IF EXISTS auth_postgraphile;

--- 

CREATE DATABASE auth;
\c auth
CREATE EXTENSION IF NOT EXISTS "pgcrypto"; 
CREATE EXTENSION IF NOT EXISTS "citext"; 

CREATE DOMAIN email AS citext
  CHECK ( value ~ '^[a-zA-Z0-9.!#$%&''*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$' );

CREATE SCHEMA auth_public; 
CREATE SCHEMA auth_private;

CREATE ROLE auth_postgraphile LOGIN PASSWORD 'password';
CREATE ROLE auth_anonymous;
GRANT auth_anonymous TO auth_postgraphile;
CREATE ROLE auth_authenticated;
GRANT auth_authenticated TO auth_postgraphile;

CREATE TABLE auth_public.user ( 
  id              serial primary key, 
  first_name      text not null check (char_length(first_name) < 80), 
  last_name       text check (char_length(last_name) < 80), 
  created_at      timestamp default now() 
);

CREATE TABLE auth_private.user_account ( 
  user_id         integer primary key references auth_public.user(id) on delete cascade, 
  email           citext not null unique, 
  password_hash   text not null 
);

CREATE TABLE auth_private.address (
  id          serial primary key,
  address_1   text,
  address_2   text,
  postal_code text,
  city        text,
  country     text
);

CREATE TABLE auth_private.contact_person (
  id              serial primary key,
  first_name      text,
  last_name       text,
  phone_number    text,
  email   email,
  facebook        text,
  instagram       text,
  twitter         text,
  website         text,  
  address_id      integer REFERENCES auth_private.address
);

CREATE TABLE auth_public.venue (
  id                  serial primary key,
  name                text,
  contact_person      integer REFERENCES auth_private.contact_person(id),
  address             integer REFERENCES auth_private.address,
  lead_time           text,
  application_dates   text,
  description         text
);

CREATE TYPE auth_public.jwt as ( 
  role    text, 
  user_id integer 
);

CREATE FUNCTION auth_public.current_user_id() RETURNS INTEGER AS $$
  SELECT current_setting('jwt.claims.user_id', true)::integer;
$$ LANGUAGE SQL STABLE;

ALTER TABLE auth_public.user ENABLE ROW LEVEL SECURITY;

CREATE POLICY select_user ON auth_public.user FOR SELECT
  using(true);

CREATE POLICY update_user ON auth_public.user FOR UPDATE TO auth_authenticated 
  using (id = auth_public.current_user_id());

CREATE POLICY delete_user ON auth_public.user FOR DELETE TO auth_authenticated 
  using (id = auth_public.current_user_id());

CREATE FUNCTION auth_public.register_user( 
  first_name  text, 
  last_name   text, 
  email       text, 
  password    text 
) RETURNS auth_public.user AS $$ 
DECLARE 
  new_user auth_public.user; 
BEGIN 
  INSERT INTO auth_public.user (first_name, last_name) values 
    (first_name, last_name) 
    returning * INTO new_user; 
    
  INSERT INTO auth_private.user_account (user_id, email, password_hash) values 
    (new_user.id, email, crypt(password, gen_salt('bf'))); 
    
  return new_user; 
END; 
$$ language plpgsql strict security definer;

CREATE FUNCTION auth_public.authenticate ( 
  email text, 
  password text 
) returns auth_public.jwt as $$ 
DECLARE 
  account auth_private.user_account; 
BEGIN 
  SELECT a.* INTO account 
  FROM auth_private.user_account as a 
  WHERE a.email = $1; 

  if account.password_hash = crypt(password, account.password_hash) then 
    return ('auth_authenticated', account.user_id)::auth_public.jwt; 
  else 
    return null; 
  end if; 
END; 
$$ language plpgsql strict security definer;

CREATE FUNCTION auth_public.current_user() RETURNS auth_public.user AS $$ 
  SELECT * 
  FROM auth_public.user 
  WHERE id = auth_public.current_user_id()
$$ language sql stable;

CREATE FUNCTION auth_public.register_venue( 
  name                    text,
  lead_time               text,
  application_dates       text,
  description             text,
  venue_address_1         text,
  venue_address_2         text,
  venue_postal_code       text,
  venue_city              text,
  venue_country           text,
  contact_first_name      text,
  contact_last_name       text,
  contact_phone_number    text,
  contact_email           email,
  contact_facebook        text,
  contact_instagram       text,
  contact_twitter         text,
  contact_website         text,  
  contact_address_1       text,
  contact_address_2       text,
  contact_postal_code     text,
  contact_city            text,
  contact_country         text
) RETURNS auth_public.venue AS $$ 
DECLARE
  new_venue_address     auth_private.address;
  new_contact_address   auth_private.address;
  new_contact_person    auth_private.contact_person;
  new_venue             auth_public.venue;
BEGIN 
  INSERT INTO auth_private.address (address_1, address_2, postal_code, city, country) values 
    (venue_address_1, venue_address_2, venue_postal_code, venue_city, venue_country)
    RETURNING * INTO new_venue_address;

  INSERT INTO auth_private.address (address_1, address_2, postal_code, city, country) values 
    (contact_address_1, contact_address_2, contact_postal_code, contact_city, contact_country)
    RETURNING * INTO new_contact_address; 

  INSERT INTO auth_private.contact_person (first_name, last_name, phone_number, email, facebook, instagram, twitter, website, address_id) 
    VALUES (contact_first_name, contact_last_name, contact_phone_number, contact_email, contact_facebook, contact_instagram, contact_twitter, contact_website, new_contact_address.id)
    RETURNING * INTO new_contact_person;

  INSERT INTO auth_public.venue (name, contact_person, address, lead_time, application_dates, description) 
    VALUES (NAME, new_contact_person.id, new_venue_address.id, lead_time, application_dates, description)
    RETURNING * INTO new_venue; 
    
  RETURN new_venue; 
END; 
$$ language plpgsql strict security definer;

GRANT USAGE ON SCHEMA auth_public TO auth_anonymous, auth_authenticated; 
GRANT SELECT ON TABLE auth_public.user TO auth_anonymous, auth_authenticated; 
GRANT SELECT ON TABLE auth_public.venue TO auth_anonymous, auth_authenticated; 
GRANT UPDATE, DELETE ON TABLE auth_public.user TO auth_authenticated; 
GRANT EXECUTE ON FUNCTION auth_public.authenticate(text, text) TO auth_anonymous, auth_authenticated; 
GRANT EXECUTE ON FUNCTION auth_public.register_venue(text, text, text, text, text, text, text, text, text, text, text, text, email, text, text, text, text, text, text, text, text, text) TO auth_anonymous, auth_authenticated; 
GRANT EXECUTE ON FUNCTION auth_public.register_user(text, text, text, text) TO auth_anonymous; 
GRANT EXECUTE ON FUNCTION auth_public.current_user() TO auth_anonymous, auth_authenticated; 

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA auth_public TO auth_anonymous, auth_authenticated;