CREATE EXTENSION pgjwt CASCADE;

\set jwt_secret `cat /run/secrets/jwt_secret`
\set auth_pass `cat /run/secrets/auth_pass`

ALTER DATABASE postgres SET "kls.jwt_secret" TO :'jwt_secret';

CREATE SCHEMA api;
CREATE SCHEMA kls;


CREATE TABLE IF NOT EXISTS kls.stations (
  id serial primary key,
  token text not null,
  description text not null,
  created timestamptz not null
);

CREATE TABLE IF NOT EXISTS api.sensor_scd30 (
  station integer,
  ts timestamptz not null DEFAULT now(),
  co2 real not null,
  humidity real not null,
  temperature real not null,
  primary key (station, ts),
  constraint fk_scd30_stations foreign key (station) REFERENCES kls.stations (id)
);

CREATE TABLE IF NOT EXISTS api.sensor_ccs811 (
  station integer,
  ts timestamptz not null DEFAULT now(),
  eco2 integer not null,
  etvoc integer not null,
  primary key (station, ts),
  constraint fk_ccs811_stations foreign key (station) REFERENCES kls.stations (id)
);

SELECT create_hypertable('api.sensor_scd30', 'ts');
SELECT create_hypertable('api.sensor_ccs811', 'ts');


CREATE OR REPLACE FUNCTION api.create_station(description text) RETURNS RECORD AS $$
DECLARE
  station_token text := encode(public.digest(gen_random_uuid()::text, 'sha256'), 'hex');
  ret RECORD;
  station_id integer;
BEGIN
  INSERT INTO kls.stations (token, description, created) VALUES
    (public.crypt(station_token, public.gen_salt('bf')), description, now()) RETURNING id INTO station_id;

  SELECT station_token, station_id INTO ret;
  RETURN ret;
END
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION api.auth_station(check_id integer, check_token text) RETURNS text AS $$
DECLARE
  stored_token text;
  jwt_token text;
BEGIN
  SELECT token FROM kls.stations WHERE id = check_id INTO stored_token;
  IF NOT stored_token = public.crypt(check_token, stored_token) THEN
    raise invalid_password using message = 'invalid station_id or token';
  END IF;

  SELECT public.sign(
    row_to_json(r), current_setting('kls.jwt_secret')
  ) AS token
  FROM (
    SELECT
      'station'::text as role,
      extract(epoch from now())::integer + 300 AS exp
  ) r
  INTO jwt_token;
  RETURN jwt_token;
END
$$ LANGUAGE plpgsql;


-------------------- Authentication

CREATE TABLE IF NOT EXISTS kls.users (
  username text PRIMARY KEY,
  password text NOT NULL,
  role name NOT NULL
);

-- ensure role for user exists
CREATE OR REPLACE FUNCTION
kls.check_role_exists() RETURNS TRIGGER AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles AS r WHERE r.rolename = new.role) THEN
    RAISE FOREIGN_KEY_VIOLATION USING MESSAGE =
      'unknown database role: ' || new.role;
    RETURN NULL;
  END IF;
  RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ensure_user_roles_exists ON kls.users;
CREATE CONSTRAINT TRIGGER ensure_user_roles_exists
  AFTER INSERT OR UPDATE ON kls.users
  FOR EACH ROW
  EXECUTE PROCEDURE kls.check_role_exists();

-- hash password
create or replace function
kls.encrypt_pass() returns trigger as $$
begin
  if tg_op = 'INSERT' or new.pass <> old.pass then
    new.pass = crypt(new.pass, gen_salt('bf'));
  end if;
  return new;
end
$$ language plpgsql;

drop trigger if exists encrypt_pass on kls.users;
create trigger encrypt_pass
  before insert or update on kls.users
  for each row
  execute procedure kls.encrypt_pass();


-- get role for give user
create or replace function
kls.user_role(username text, password text) returns name
  language plpgsql
  as $$
begin
  return (
  select role from kls.users
   where users.username = user_role.username
     and users.password = crypt(user_role.password, users.password)
  );
end;
$$;



CREATE ROLE authenticator noinherit LOGIN PASSWORD :'auth_pass';
CREATE ROLE anon nologin;
CREATE ROLE station nologin;

GRANT USAGE ON SCHEMA api, kls to anon;
GRANT USAGE ON SCHEMA api to station;

GRANT anon TO authenticator;
GRANT station TO authenticator;

GRANT INSERT ON api.sensor_scd30, api.sensor_ccs811 TO station;
GRANT SELECT ON kls.stations TO anon;
GRANT EXECUTE ON FUNCTION api.auth_station TO anon;
