create table todos (
    id serial primary key,
    done boolean not null default false,
    task text not null,
    due timestamptz
);
insert into todos (task) values
    ('finish tutorial 0'), ('pat self on back');

create role anon nologin;
grant select on todos to anon;

create role authenticator noinherit login password :'auth_pass';
grant anon to authenticator;
