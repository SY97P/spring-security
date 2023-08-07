DROP TABLE IF EXISTS users CASCADE;
drop table if exists authorities cascade;

CREATE TABLE users
(
    username varchar(20) not null ,
    password varchar(80) not null ,
    enabled boolean not null default false,
    primary key (username)
);

create table authorities
(
    username varchar(20) not null ,
    authority varchar(20) not null ,
    primary key (username)
);