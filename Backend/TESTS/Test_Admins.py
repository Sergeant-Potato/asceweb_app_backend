from sqlalchemy.orm import Session
from Backend.DATABASE.Administrators_Table import Administrators_Table
import Backend.SCHEMAS.Administrators_Schemas as adminSchema
from Backend.API.Security import Secuirity as sc
from pydantic import SecretStr


__sc = sc()
'''
    If working properly, functions to be moved elsewhere in the future.
'''

def getAdmins(db: Session):
    entries = db.query(Administrators_Table).all()
    return [adminSchema.Administrator_LookAccount_OUT(idAdministrators=entry.idadministrators,name=entry.name,userName=entry.username,password=entry.password,email=entry.email,adminLevel=entry.admin_level, createdAt=entry.created_at, updatedAt=entry.updated_at) for entry in entries]

def getAdminbyEmail(db: Session, email: str):
    return db.query(Administrators_Table).filter(Administrators_Table.email == email).first()

def getAdminbyUserName(db: Session, username: str):
    return db.query(Administrators_Table).filter(Administrators_Table.username == username).first()

def createAdmin(db: Session, admin: adminSchema.Administrator_CreateAccount_OUT):
    dbAdmin = Administrators_Table(name=admin.name, email=admin.email, username=admin.userName.get_secret_value(), password=__sc.encrypt(admin.passwd.get_secret_value()), admin_level=admin.adminLevel,created_at=admin.createdAt, updated_at=admin.updatedAt)
    db.add(dbAdmin)
    db.commit()
    db.refresh(dbAdmin)
    return admin

def validateUser(db: Session,user: adminSchema.Administrator_LoginAccount_OUT):
    username = user.userName.get_secret_value()
    password = user.passwd.get_secret_value()
    database = db.query(Administrators_Table.username, Administrators_Table.password).filter(Administrators_Table.username == username).first()
    # print(database, database[0], database[1])
    if username == database[0] and __sc.verify(password,database[1]):
        return {'msg': "User validated"}
    else:
        return {'msg':'Wrong username or password'}

def loginAdmin(db: Session, admin: adminSchema.Administrator_LoginAccount_OUT) -> bool:
    entries = db.query(Administrators_Table).all()
    for entry in entries:
        if(__sc.verify(admin.passwd.get_secret_value(),entry.password) == True):
            return True
    return False

#------------------------------------------------TOKEN FUNCTIONS
def validateUsers(db: Session,username:str,password:SecretStr, token: str = None):
    """Validate username and password as well as token"""
    schema = adminSchema.Administrator_LoginAccount_OUT(userName=username, passwd=password)
    db_information = db.query(Administrators_Table.username, Administrators_Table.password, Administrators_Table.admin_level).filter(Administrators_Table.username == schema.userName).first()
    try:
        if not token and __sc.validateUsername(schema.userName, db_information[0]) and __sc.verify(schema.passwd.get_secret_value(), db_information[1]):
            return {'status_code': 200, 'body': __sc.createToken({'username':schema.userName, 'admin_level': db_information[2]})}
        elif token and __sc.validate_exp_token(token) == True and __sc.validate_token_payload(token, schema.userName, db_information[2]):
            return {'status_code': 200, 'body': 'Successful authentication'}
        elif token and not __sc.validate_exp_token(token) and  __sc.validate_token_payload(token, schema.userName, db_information[2]):
            return {'status_code': 200, 'body': __sc.createToken({'username':schema.userName, 'admin_level': db_information[2]})}
        elif token and not __sc.validate_exp_token(token) and not __sc.validate_token_payload(token, schema.userName, db_information[2]):
            return {'status_code': 201, 'body':'Invalid token'}
        else:
            raise Exception

    except Exception as e:
        return {'status_code': 401, 'body': 'Invalid username of password'} 