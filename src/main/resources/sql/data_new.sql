INSERT INTO permissions(id, name)
VALUES (1, 'ROLE_USER'),
       (2, 'ROLE_ADMIN')
;

INSERT INTO groups(id, name)
VALUES (1, 'USER_GROUP'),
       (2, 'ADMIN_GROUP')
;

INSERT INTO group_permission(id, group_id, permission_id)
VALUES (1, 1, 1),
       (2, 2, 1),
       (3, 2, 2)
;

INSERT INTO users(id, login_id, passwd, group_id)
VALUES (1, 'user', '$2a$10$OJ7pQMD3mNqmxLctJhPyBOrYqcZk1H7Zzzz09KRmLxqZVtw89oHCG',1),
       (2, 'admin', '$2a$10$h66x2suuuvrq7mnswYqBcePkDUaxOe3aI7XLpSBwbWKAXVVsysKlC',2)
;
