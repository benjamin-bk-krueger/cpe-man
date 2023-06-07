CREATE TABLE student (
    student_id SERIAL PRIMARY KEY,
    student_name VARCHAR ( 100 ) UNIQUE NOT NULL,
    student_mail VARCHAR ( 100 ) UNIQUE NOT NULL,
    student_desc VARCHAR ( 1024 ),
    student_pass VARCHAR ( 256 ),
    student_img VARCHAR ( 384 ),
    student_role VARCHAR ( 20 ) NOT NULL,
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

CREATE TABLE organization (
    organization_id SERIAL PRIMARY KEY,
    student_id INT REFERENCES student ( student_id ),
    organization_name VARCHAR ( 100 ) UNIQUE NOT NULL,
    organization_desc VARCHAR ( 1024 ),
    organization_url VARCHAR ( 256 ),
    organization_img VARCHAR ( 384),
    created timestamp default current_timestamp,
    modified timestamp default current_timestamp
);

CREATE TABLE certification (
    certification_id SERIAL PRIMARY KEY,
    student_id INT REFERENCES  student ( student_id ),
    organization_id INT REFERENCES organization ( organization_id ),
    certification_name VARCHAR ( 100 ) NOT NULL,
    certification_desc VARCHAR ( 1024 ),
    certification_url VARCHAR ( 256 ),
    certification_img VARCHAR ( 384),
    cycle_length INT default 3,
    requirement_year INT default 20 NOT NULL,
    requirement_full INT default 90 NOT NULL,
    created timestamp default current_timestamp,
    modified timestamp default current_timestamp
);

CREATE UNIQUE INDEX idx_certification_name
ON certification ( certification_name, organization_id );

CREATE TABLE cycle (
    cycle_id SERIAL PRIMARY KEY,
    student_id INT REFERENCES  student ( student_id ),
    certification_id INT REFERENCES certification ( certification_id ),
    certification_date TIMESTAMP,
    cycle_start TIMESTAMP NOT NULL,
    created timestamp default current_timestamp,
    modified timestamp default current_timestamp
);

CREATE UNIQUE INDEX idx_cycle_id
ON cycle ( certification_id, student_id );

CREATE TABLE cpe (
    cpe_id SERIAL PRIMARY KEY,
    student_id INT REFERENCES  student ( student_id ),
    cpe_name VARCHAR ( 100 ) NOT NULL,
    activity_start TIMESTAMP,
    activity_end TIMESTAMP NOT NULL,
    credits DECIMAL DEFAULT 1.00 NOT NULL,
    sponsor VARCHAR ( 100 ),
    attachment VARCHAR ( 384),
    created timestamp default current_timestamp,
    modified timestamp default current_timestamp
);

CREATE UNIQUE INDEX idx_cpe_name
ON cpe ( cpe_name, activity_end );

CREATE TABLE cpelink (
    cpelink_id SERIAL PRIMARY KEY,
    student_id INT REFERENCES  student ( student_id ),
    cpe_id INT REFERENCES  cpe ( cpe_id ),
    cycle_id INT REFERENCES  cycle ( cycle_id ),
    created timestamp default current_timestamp,
    modified timestamp default current_timestamp
);

CREATE UNIQUE INDEX idx_cpelink_id
ON cpelink ( cpe_id, cycle_id );

CREATE OR REPLACE FUNCTION update_modified_column()   
RETURNS TRIGGER AS $$
BEGIN
    NEW.modified = now();
    RETURN NEW;   
END;
$$ language 'plpgsql';

CREATE TRIGGER update_student_modtime BEFORE UPDATE ON student FOR EACH ROW EXECUTE PROCEDURE  update_modified_column();
CREATE TRIGGER update_invitation_modtime BEFORE UPDATE ON invitation FOR EACH ROW EXECUTE PROCEDURE  update_modified_column();
CREATE TRIGGER update_organization_modtime BEFORE UPDATE ON organization FOR EACH ROW EXECUTE PROCEDURE  update_modified_column();
CREATE TRIGGER update_certification_modtime BEFORE UPDATE ON certification FOR EACH ROW EXECUTE PROCEDURE  update_modified_column();
CREATE TRIGGER update_cycle_modtime BEFORE UPDATE ON cycle FOR EACH ROW EXECUTE PROCEDURE  update_modified_column();
CREATE TRIGGER update_cpe_modtime BEFORE UPDATE ON cpe FOR EACH ROW EXECUTE PROCEDURE  update_modified_column();
CREATE TRIGGER update_cpelink_modtime BEFORE UPDATE ON cpelink FOR EACH ROW EXECUTE PROCEDURE  update_modified_column();

-- Default credentials, need to be changed on production stage
INSERT INTO invitation(invitation_code, invitation_role, invitation_forever) VALUES ('heureka', 'student', 1);
INSERT INTO invitation(invitation_code, invitation_role, invitation_forever) VALUES ('sunshine', 'admin', 0);
