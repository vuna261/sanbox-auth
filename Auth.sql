create table user_role
(
    id           int auto_increment
        primary key,
    user_id      bigint       not null,
    role         varchar(255) not null,
    created_date datetime     null,
    updated_date datetime     null,
    created_by   varchar(255) null,
    updated_by   varchar(255) null
);

create table users
(
    id             bigint auto_increment
        primary key,
    email          varchar(255)         null,
    email_verified tinyint(1) default 0 null,
    image_url      varchar(255)         null,
    is_active      tinyint(1) default 1 null,
    name           varchar(255)         null,
    password       varchar(500)         null,
    provider       varchar(255)         null,
    provider_id    varchar(255)         null,
    is_default     tinyint(1) default 0 null,
    verify_code    varchar(255)         null
);

