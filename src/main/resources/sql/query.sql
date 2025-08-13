CREATE TABLE users (
                       id BIGSERIAL PRIMARY KEY,
                       firstname VARCHAR(255) NOT NULL,
                       lastname VARCHAR(255),
                       email VARCHAR(100) NOT NULL UNIQUE,
                       password VARCHAR(255) NOT NULL,
                       role VARCHAR(50),
                       enabled BOOLEAN DEFAULT FALSE
);


CREATE TABLE verification_tokens (
                                     id BIGSERIAL PRIMARY KEY,
                                     token VARCHAR(255) NOT NULL UNIQUE,
                                     user_id BIGINT NOT NULL REFERENCES users(id),
                                     expiry_timestamp TIMESTAMP NOT NULL
);


CREATE TABLE password_reset_tokens (
                                       id BIGSERIAL PRIMARY KEY,
                                       user_id BIGINT NOT NULL,
                                       token VARCHAR(255) NOT NULL UNIQUE,
                                       expiry_date TIMESTAMP NOT NULL,
                                       is_used BOOLEAN DEFAULT FALSE,
                                       FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);


CREATE TABLE password_reset_otps (
                                     id BIGSERIAL PRIMARY KEY,
                                     otp VARCHAR(255) NOT NULL,
                                     user_id BIGINT NOT NULL UNIQUE,
                                     expiry_date TIMESTAMP,
                                     CONSTRAINT fk_password_reset_otps_user FOREIGN KEY (user_id) REFERENCES users (id)
);

