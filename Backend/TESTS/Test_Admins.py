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
    try:
        entries = db.query(Administrators_Table).all()
        return [adminSchema.Administrator_GETTER(idAdministrators=entry.idadministrators,name=entry.name,userName=entry.username,password=entry.password,email=entry.email,adminLevel=entry.admin_level, createdAt=entry.created_at, updatedAt=entry.updated_at) for entry in entries]
    except Exception as e:
        return e
    
def getAdminbyEmail(db: Session, email: str):
    try:
        return db.query(Administrators_Table).filter(Administrators_Table.email == email).first()
    except Exception as e:
        return e

def getAdminbyUserName(db: Session, username: str):
    try:
        return db.query(Administrators_Table).filter(Administrators_Table.username == username).first()
    except Exception as e:
        return e

def createAdmin(db: Session, admin: adminSchema.Administrator_CreateAccount_DB):
    try:
        dbAdmin = Administrators_Table(name=admin.name, email=admin.email, username=admin.userName, password=__sc.encryptHash(admin.passwd.get_secret_value()), admin_level=admin.adminLevel,created_at=admin.createdAt, updated_at=admin.updatedAt)
        db.add(dbAdmin)
        db.commit()
        db.refresh(dbAdmin)
        return admin
    except Exception as e:
        return e

#------------------------------------------------TOKEN FUNCTIONS
"""
1. function to validate username and password
2. function to create token
3. function to validate token from frontend
   a. Get token
   b. Validate username and password from login
   c. Get username and verify username in database
   d. If token is expired, then create new token

"""

class HttpReturn():
    def __init__(self, status_code: int, detail: dict):
        self.status_code = status_code
        self.detail = detail


def loginAdmin(db: Session, admin: adminSchema.Administrator_LoginAccount_DB) -> list:
    """Validate username and password as well as token"""
    ''' Mira mano, lo hice asi ya que el codigo que me enviaste tiene tres status codes iguales y uno diferente. Hace tus ifs, pero retorn dos
        cosas, un entero, el cual, funcionara como un use case, es decir: si es 1, paso algo, si es 2, pasa otra cosa... etc.; tambien, retorna
        o el token o un texto. No debe haber problema con esto por el token y el texto ser strings. Busca el endpoint que usa esto en el main.'''
    try:
        db_information = db.query(Administrators_Table.username, Administrators_Table.password, Administrators_Table.admin_level).filter(Administrators_Table.username == admin.userName).first()
        if __sc.validateUsername(admin.userName, db_information[0]) and __sc.verify(admin.passwd.get_secret_value(), db_information[1]) and not admin.token:
            return [1, __sc.createToken({'username': admin.userName, 'admin_level':db_information[2]})]
        elif admin.token and __sc.validateToken(admin.userName,db_information[2],admin.token) == [True, True]:
            return [2, "Successful Authenticacion!"]
        elif admin.token and __sc.validateToken(admin.userName,db_information[2],admin.token) == [True, False]:
            return [3, __sc.createToken({'username': admin.userName, 'admin_level':db_information[2]})]
        elif admin.token and __sc.validateToken(admin.userName,db_information[2],admin.token) == [False, True]:
            return [4, "Invalid Token"]
        else:
            raise Exception
    except:
        return ValueError("Invalid Username or Password")
        
        
def changeAdminPasswd(db: Session, admin: adminSchema.Administrator_ChangePasswd_DB):
    try:
        if db.query(Administrators_Table).filter(admin.userName == Administrators_Table.username and __sc.validateHash(admin.oldPasswd, Administrators_Table.password)).update({'password': __sc.encryptHash(admin.newPasswd)}):
            return True
        return False
    except Exception as e:
        return e

