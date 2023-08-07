insert into users(username, password, enabled)
values ('user', '{noop}user123', true),
       ('admin', '{noop}admin123', true)
;

insert into authorities(username, authority)
values ('user', 'ROLE_USER'),
       ('admin', 'ROLE_ADMIN')
;