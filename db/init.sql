CREATE TABLE creator (
    creator_id SERIAL PRIMARY KEY,
    creator_name VARCHAR ( 100 ) UNIQUE NOT NULL,
    creator_mail VARCHAR ( 100 ) UNIQUE NOT NULL,
    creator_desc VARCHAR ( 1024 ),
    creator_pass VARCHAR ( 256 ),
    creator_img VARCHAR ( 384 ),
    creator_role VARCHAR ( 20 ),
    active INT default 0,
    notification INT default 0,
    password_reset VARCHAR ( 100 ),
    created timestamp default current_timestamp,
    modified timestamp default current_timestamp
);

CREATE TABLE invitation (
    invitation_id SERIAL PRIMARY KEY,
    invitation_code VARCHAR ( 20 ) UNIQUE NOT NULL,
    invitation_role VARCHAR ( 20 ) NOT NULL,
    invitation_forever INT default 0,
    invitation_taken INT default 0,
    created timestamp default current_timestamp,
    modified timestamp default current_timestamp
);

CREATE TABLE provider (
    provider_id SERIAL PRIMARY KEY,
    creator_id INT REFERENCES creator ( creator_id ),
    provider_name VARCHAR ( 100 ),
    provider_desc VARCHAR ( 1024 ),
    provider_url VARCHAR ( 256 ),
    provider_img VARCHAR ( 384),
    created timestamp default current_timestamp,
    modified timestamp default current_timestamp
);

CREATE UNIQUE INDEX idx_provider_name
ON provider ( provider_name, creator_id );

CREATE OR REPLACE FUNCTION update_modified_column()   
RETURNS TRIGGER AS $$
BEGIN
    NEW.modified = now();
    RETURN NEW;   
END;
$$ language 'plpgsql';

CREATE TRIGGER update_creator_modtime BEFORE UPDATE ON creator FOR EACH ROW EXECUTE PROCEDURE  update_modified_column();
CREATE TRIGGER update_invitation_modtime BEFORE UPDATE ON invitation FOR EACH ROW EXECUTE PROCEDURE  update_modified_column();
CREATE TRIGGER update_provider_modtime BEFORE UPDATE ON provider FOR EACH ROW EXECUTE PROCEDURE  update_modified_column();

-- Default credentials, need to be changed on production stage
INSERT INTO invitation(invitation_code, invitation_role, invitation_forever) VALUES ('heureka', 'creator', 0);
INSERT INTO invitation(invitation_code, invitation_role, invitation_forever) VALUES ('sunshine', 'user', 1);
