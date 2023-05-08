from pydantic import BaseModel as Schema, ValidationError, validator, root_validator, EmailStr, SecretStr
import datetime as dt
from typing import Any


'''
    ----------------------------------------------------------------
                    SCHEMAS FOR INPUTING DATA
    ----------------------------------------------------------------
'''
'''
    Base Schema for Administrator

    It handles the inputs for userName and passwd
'''

class __Administrator_Basic_INPUTS(Schema):
    userName: str
    passwd: SecretStr

    @validator('*', allow_reuse=True, pre=True)
    def isEmpty(cls, value: str | dt.datetime):
        if type(value) is str and (value == "" or value == None):
            raise ValueError("None of the Fields can be empty!")
        return value
    
    @root_validator(allow_reuse=True, pre=True)
    def isSame(cls, values: dict):
        '''
            These two lines may be a vuln
        '''
        val1 = values.get("userName")
        val2 = values.get("passwd")
        print(values)
        if val1 == val2:
            # print(values)
            raise ValueError("The User Name and passwdord cannot be the same.")
        return values
    
    @validator('userName', allow_reuse=True)
    def isUserName(cls, value: str):
        if len(value) < 5:
            raise ValueError("The User Name must have more than four (4) characters.")
        if value.isalnum() == False:
            raise ValueError("An User Name must contain alphabetic and numeric characters.")
        if value.islower() or value.isupper():
            raise ValueError("A User Name must have both upper - case and lower - case characters.")
        return value

    @validator('passwd', allow_reuse=True)
    def isPasswd(cls, value: SecretStr):
        if len(value) < 8:
            raise ValueError("The Password must have at least eight (8) characters.")
        if value.get_secret_value().islower() or value.get_secret_value().isupper():
            raise ValueError("A Password must have both upper - case and lower - case characters.")
        if all(v.isalnum() or v in ('!', '@', '#', '$', '%', '&') for v in value.get_secret_value()) == False:
            raise ValueError("A Password must have numbers, letters and symbols.")
        return value

'''
    Subclass of Base Administrator Class for the creation of accounts

    It does not validate emails, sinde EmailStr does that.
'''
class Administrator_CreateAccount_INPUTS(__Administrator_Basic_INPUTS):    #   ACCOUNT CREATING INPUTS
    """SETTER para validar inputs y luego enviar a la base de datos"""
    name: str
    email: EmailStr
    adminLevel: str
    createdAt: dt.datetime = dt.datetime.now()
    updatedAt: dt.datetime = dt.datetime.now()

    masterAdminLevel: str

    @validator('name', allow_reuse=True)
    def isName(cls, value: str):
     if any(v[0].islower() for v in value.split()):
         raise ValueError("All parts of any name should contain upper - case characters.")
     if any(v.isalpha() for v in value.split()) == False:
         raise ValueError("A name only contains letters.")
     return value
    
    @root_validator(allow_reuse=True)
    def isAdminLevel(cls, values: dict):
        val1 = values.get("adminLevel")
        val2 = values.get("masterAdminLevel")

        if (len(val1) <= 0 or len(val1) > 2) and (len(val2) <= 0 or len(val2) > 2):
            raise ValueError("The admin levels value must have two (2) characters at all times.")
        if not(val1 == "MA" or val1 == "GA"):
            raise ValueError("The admin level value does not have any of the accepted values.")
        if not(val2 == "MA"):
            raise ValueError("This account does not have the necessary priviliges to create new admins.")
        return values
    
    @validator('masterAdminLevel', allow_reuse=True)
    def isMasterAdminLevel(cls, value: str):
        if (len(value) <= 0 or len(value) > 2):
            raise ValueError("The admin level value must have two (2) characters at all times.")
        if value != "MA":
            raise ValueError("This account does not have the necessary priviliges to edit admins.")
        return value
    
    class Config:
        orm_mode = True

'''
    Subclass of Base Administrator Account for Login
    
    Only require userName and passwd
'''
class Administrator_LoginAccount_INPUTS(__Administrator_Basic_INPUTS):
    
    token: str = None

    class Config:
        orm_mode = True

class Administrator_ChangePasswd_INPUTS(Schema):
    userName: str
    passwd: SecretStr
    newPasswd: SecretStr
    updatedAt: dt.datetime = dt.datetime.now()

    masterAdminLevel: str = None
    
    @root_validator(allow_reuse=True)
    def isSame(cls, values: dict):
        '''
            These two lines may be a vuln
        '''
        val1 = values.get("passwd")
        val2 = values.get("newPasswd")
        if val1 == val2:
            raise ValueError("The Old Password and New Password cannot be the same.")
        return values
    
    @validator('userName', allow_reuse=True)
    def isUserName(cls, value: str):
        if len(value) < 5:
            raise ValueError("The User Name must have more than four (4) characters.")
        if value.isalnum() == False:
            raise ValueError("An User Name must contain alphabetic and numeric characters.")
        if value.islower() or value.isupper():
            raise ValueError("A User Name must have both upper - case and lower - case characters.")
        return value

    @validator('passwd', allow_reuse=True)
    def isPasswd(cls, value: SecretStr):
        if len(value) < 8:
            raise ValueError("The Password must have at least eight (8) characters.")
        if value.get_secret_value().islower() or value.get_secret_value().isupper():
            raise ValueError("A Password must have both upper - case and lower - case characters.")
        if all(v.isalnum() or v in ('!', '@', '#', '$', '%', '&') for v in value.get_secret_value()) == False:
            raise ValueError("A Password must have numbers, letters and symbols.")
        return value
    
    @validator('newPasswd', allow_reuse=True)
    def isPasswd(cls, value: SecretStr):
        if len(value) < 8:
            raise ValueError("The New Password must have at least eight (8) characters.")
        if value.get_secret_value().islower() or value.get_secret_value().isupper():
            raise ValueError("A New Password must have both upper - case and lower - case characters.")
        if all(v.isalnum() or v in ('!', '@', '#', '$', '%', '&') for v in value.get_secret_value()) == False:
            raise ValueError("A New Password must have numbers, letters and symbols.")
        return value
    
    @validator('masterAdminLevel', allow_reuse=True)
    def isMasterAdminLevel(cls, value: str):
        if value != None:
            if (len(value) <= 0 or len(value) > 2):
                raise ValueError("The admin level value must have two (2) characters at all times.")
            if value != "MA":
                raise ValueError("This account does not have the necessary priviliges to edit admins.")
        return value
    
    class Config:
        orm_mode = True



class Administrator_ChangeName_INPUTS(Schema):
    userName: str
    newName: str
    updatedAt: dt.datetime = dt.datetime.now()

    @validator('*', allow_reuse=True, pre=True)
    def isEmpty(cls, value: str | dt.datetime):
        if type(value) is str and (value == "" or value == None):
            raise ValueError("None of the Fields can be empty!")
        return value
    
    @validator('userName', allow_reuse=True)
    def isUserName(cls, value: str):
        if len(value) < 5:
            raise ValueError("The User Name must have more than four (4) characters.")
        if value.isalnum() == False:
            raise ValueError("An User Name must contain alphabetic and numeric characters.")
        if value.islower() or value.isupper():
            raise ValueError("A User Name must have both upper - case and lower - case characters.")
        return value
    
    @validator('newName', allow_reuse=True)
    def isName(cls, value: str):
     if any(v[0].islower() for v in value.split()):
         raise ValueError("All parts of any name should contain upper - case characters.")
     if any(v.isalpha() for v in value.split()) == False:
         raise ValueError("A name only contains letters.")
     return value

    class Config:
        orm_mode = True

class Administrator_ChangeEmail_INPUTS(Schema):
    userName: str
    newEmail: EmailStr
    updatedAt: dt.datetime = dt.datetime.now()

    @validator('*', allow_reuse=True, pre=True)
    def isEmpty(cls, value: str | dt.datetime):
        if type(value) is str and (value == "" or value == None):
            raise ValueError("None of the Fields can be empty!")
        return value
    
    @validator('userName', allow_reuse=True)
    def isUserName(cls, value: str):
        if len(value) < 5:
            raise ValueError("The User Name must have more than four (4) characters.")
        if value.isalnum() == False:
            raise ValueError("An User Name must contain alphabetic and numeric characters.")
        if value.islower() or value.isupper():
            raise ValueError("A User Name must have both upper - case and lower - case characters.")
        return value    
    class Config:
        orm_mode: True
    


class Administrator_ChangeAll_INPUTS(Administrator_ChangePasswd_INPUTS):
    newName: str
    newEmail: EmailStr
    newLevel: str

    @validator('newName', allow_reuse=True)
    def isName(cls, value: str):
     if any(v[0].islower() for v in value.split()):
         raise ValueError("All parts of any name should contain upper - case characters.")
     if any(v.isalpha() for v in value.split()) == False:
         raise ValueError("A name only contains letters.")
     return value
    
    @validator('newLevel', allow_reuse=True)
    def isAdminLevel(cls, value: str):
        if len(value) <= 0 or len(value) > 2:
            raise ValueError("The admin level value must have two (2) characters at all times.")
        if not(value == "MA" or value == "GA"):
            raise ValueError("The admin level value does not have any of the accepted values.")
        return value
    class Config:
        orm_mode: True


class Administrator_Delete_Entry_INPUTS(Schema):
    masterAdminLevel: str
    state: str = "--i"
    userName: str = None

    @validator('*', allow_reuse=True, pre=True)
    def isEmpty(cls, value: str | dt.datetime):
        if type(value) is str and (value == "" or value == None):
            raise ValueError("None of the Fields can be empty!")
        return value
    
    @validator('userName', allow_reuse=True)
    def isUserName(cls, value: str):
        if value != None:
            if len(value) < 5:
                raise ValueError("The User Name must have more than four (4) characters.")
            if value.isalnum() == False:
                raise ValueError("An User Name must contain alphabetic and numeric characters.")
            if value.islower() or value.isupper():
                raise ValueError("A User Name must have both upper - case and lower - case characters.")
        return value
    
    @validator('state', allow_reuse=True)
    def isState(cls, value: str):
        if not(value == "--i" or value == "--a"):
            raise ValueError("The state of deletion is not of any of the accepted values.")
        return value
    
    @validator('masterAdminLevel', allow_reuse=True)
    def isMasterAdminLevel(cls, value: str):
        if (len(value) <= 0 or len(value) > 2):
            raise ValueError("The admin level value must have two (2) characters at all times.")
        if value != "MA":
            raise ValueError("This account does not have the necessary priviliges to edit admins.")
        return value
    
    class Config:
        orm_mode = True

'''
    ----------------------------------------------------------------------------
                            Response Models
    ----------------------------------------------------------------------------
    This data is to be outputed to table
'''

class Administrator_CreateAccount_DB(Schema):
    """SETTER Para la base de datos"""
    userName: str
    passwd: SecretStr
    name: str
    email: EmailStr
    adminLevel: str
    createdAt: dt.datetime
    updatedAt: dt.datetime

    class Config:
        orm_mode = True

'''
    These are all the values that should be returned if an admin account is returnd.
'''
class Administrator_GETTER(Schema): 
    """Send data to frontend dashboard table"""
    idAdministrators: int
    userName: str
    password: str
    name: str
    email: EmailStr
    adminLevel: str
    createdAt: dt.datetime
    updatedAt: dt.datetime

    class Config:
        orm_mode = True

class Administrator_LoginAccount_DB(Schema):
    """ GET to validate information username and password from database"""
    userName: str
    passwd: SecretStr
    token: str = None

    class Config:
        orm_mode = True

class Administrator_ChangePasswd_DB(Schema):
    userName: str
    passwd: SecretStr
    newPasswd: SecretStr
    updatedAt: dt.datetime

    masterAdminLevel: str

    class Config:
        orm_mode = True

class Administrator_ChangeName_DB(Schema):
    userName: str
    name: str
    updatedAt: dt.datetime

    class Config:
        orm_mode = True

class Administrator_ChangeEmail_DB(Schema):
    userName: str
    email: str
    updatedAt: dt.datetime

    class Config:
        orm_mode = True

class Administrator_ChangeAll_DB(Schema):
    userName: str
    
    newPasswd: SecretStr
    newName: str
    newEmail: str
    newLevel: str
    updatedAt: dt.datetime

    masterAdminLevel: str

    class Config:
        orm_mode = True

class Administrator_Validate_User(Schema):
    """Schema to send a dictionary when validating a user in login"""
    status_code: Any
    body: Any

    class Config:
        orm_mode = True

if __name__ == "__main__":
    '''
        First local test to check if all values to create an admin account are parsed correctly.
    '''
    try:
        admin1 = Administrator_CreateAccount_INPUTS(userName="Pepe112", passwd="Every#one313", name="Pepe The Frog", email="pepe@gmail.com", adminLevel="GA")
        admin2 = Administrator_CreateAccount_INPUTS(userName="Pepe221", passwd="12pPpppppppp", name=" ", email="datapp.com", adminLevel="LA")
        #   looking = Administrator_LookAccount(idAdministrators=-1)
    except ValidationError as e:
        print(e)