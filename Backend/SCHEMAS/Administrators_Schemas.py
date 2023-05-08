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

    masterAdminToken: str

    @validator('name', allow_reuse=True)
    def isName(cls, value: str):
     if any(v[0].islower() for v in value.split()):
         raise ValueError("All parts of any name should contain upper - case characters.")
     if any(v.isalpha() for v in value.split()) == False:
         raise ValueError("A name only contains letters.")
     return value
    
    @validator('adminLevel',allow_reuse=True)
    def isAdminLevel(cls, value: str):

        if (len(value) <= 0 or len(value) > 2):
            raise ValueError("The admin levels value must have two (2) characters at all times.")
        if not(value == "MA" or value == "GA"):
            raise ValueError("The admin level value does not have any of the accepted values.")
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

class Administrator_ChangePasswdEmail_INPUTS(Schema):
    userName: str
    newPasswd: SecretStr = None
    newEmail: EmailStr = None
    updatedAt: dt.datetime = dt.datetime.now()

    masterAdminToken: str
    
    @validator('userName', allow_reuse=True)
    def isUserName(cls, value: str):
        if len(value) < 5:
            raise ValueError("The User Name must have more than four (4) characters.")
        if value.isalnum() == False:
            raise ValueError("An User Name must contain alphabetic and numeric characters.")
        if value.islower() or value.isupper():
            raise ValueError("A User Name must have both upper - case and lower - case characters.")
        return value
    
    @validator('newPasswd', allow_reuse=True)
    def isPasswd(cls, value: SecretStr):
        if value != None:
            if len(value) < 8:
                raise ValueError("The New Password must have at least eight (8) characters.")
            if value.get_secret_value().islower() or value.get_secret_value().isupper():
                raise ValueError("A New Password must have both upper - case and lower - case characters.")
            if all(v.isalnum() or v in ('!', '@', '#', '$', '%', '&') for v in value.get_secret_value()) == False:
                raise ValueError("A New Password must have numbers, letters and symbols.")
        return value
    
    class Config:
        orm_mode = True



# class Administrator_ChangeName_INPUTS(Schema):
#     userName: str
#     newName: str
#     updatedAt: dt.datetime = dt.datetime.now()

#     masterAdminToken: str = None

#     @validator('*', allow_reuse=True, pre=True)
#     def isEmpty(cls, value: str | dt.datetime):
#         if type(value) is str and (value == "" or value == None):
#             raise ValueError("None of the Fields can be empty!")
#         return value
    
#     @validator('userName', allow_reuse=True)
#     def isUserName(cls, value: str):
#         if len(value) < 5:
#             raise ValueError("The User Name must have more than four (4) characters.")
#         if value.isalnum() == False:
#             raise ValueError("An User Name must contain alphabetic and numeric characters.")
#         if value.islower() or value.isupper():
#             raise ValueError("A User Name must have both upper - case and lower - case characters.")
#         return value
    
#     @validator('newName', allow_reuse=True)
#     def isName(cls, value: str):
#      if any(v[0].islower() for v in value.split()):
#          raise ValueError("All parts of any name should contain upper - case characters.")
#      if any(v.isalpha() for v in value.split()) == False:
#          raise ValueError("A name only contains letters.")
#      return value

#     class Config:
#         orm_mode = True

# class Administrator_ChangeEmail_INPUTS(Schema):
#     userName: str
#     newEmail: EmailStr
#     updatedAt: dt.datetime = dt.datetime.now()

#     masterAdminToken: str = None

#     @validator('*', allow_reuse=True, pre=True)
#     def isEmpty(cls, value: str | dt.datetime):
#         if type(value) is str and (value == "" or value == None):
#             raise ValueError("None of the Fields can be empty!")
#         return value
    
#     @validator('userName', allow_reuse=True)
#     def isUserName(cls, value: str):
#         if len(value) < 5:
#             raise ValueError("The User Name must have more than four (4) characters.")
#         if value.isalnum() == False:
#             raise ValueError("An User Name must contain alphabetic and numeric characters.")
#         if value.islower() or value.isupper():
#             raise ValueError("A User Name must have both upper - case and lower - case characters.")
#         return value    
#     class Config:
#         orm_mode: True
    


# class Administrator_ChangeAll_INPUTS(Administrator_ChangePasswdEmail_INPUTS):
#     newName: str
#     newEmail: EmailStr
#     newLevel: str

#     @validator('newName', allow_reuse=True)
#     def isName(cls, value: str):
#      if any(v[0].islower() for v in value.split()):
#          raise ValueError("All parts of any name should contain upper - case characters.")
#      if any(v.isalpha() for v in value.split()) == False:
#          raise ValueError("A name only contains letters.")
#      return value
    
#     @validator('newLevel', allow_reuse=True)
#     def isAdminLevel(cls, value: str):
#         if len(value) <= 0 or len(value) > 2:
#             raise ValueError("The admin level value must have two (2) characters at all times.")
#         if not(value == "MA" or value == "GA"):
#             raise ValueError("The admin level value does not have any of the accepted values.")
#         return value
#     class Config:
#         orm_mode: True


class Administrator_Delete_Entry_INPUTS(Schema):
    masterAdminToken: str
    email: EmailStr

    @validator('*', allow_reuse=True, pre=True)
    def isEmpty(cls, value: str | dt.datetime):
        if type(value) is str and (value == "" or value == None):
            raise ValueError("None of the Fields can be empty!")
        return value
    class Config:
        orm_mode = True

class Administrator_MasterAdminToken(Schema):
    masterAdminToken: str

    @validator('*', allow_reuse=True, pre=True)
    def isEmpty(cls, value: str | dt.datetime):
        if type(value) is str and (value == "" or value == None):
            raise ValueError("None of the Fields can be empty!")
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

    masterAdminToken: str

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

class Administrator_ChangePasswdEmail_DB(Schema):
    userName: str
    newPasswd: SecretStr
    newEmail: EmailStr
    updatedAt: dt.datetime

    masterAdminToken: str

    class Config:
        orm_mode = True

# class Administrator_ChangeName_DB(Schema):
#     userName: str
#     name: str
#     updatedAt: dt.datetime

#     masterAdminToken: str

#     class Config:
#         orm_mode = True

# class Administrator_ChangeEmail_DB(Schema):
#     userName: str
#     email: str
#     updatedAt: dt.datetime

#     masterAdminToken: str

#     class Config:
#         orm_mode = True

# class Administrator_ChangeAll_DB(Schema):
#     userName: str
    
#     newPasswd: SecretStr
#     newName: str
#     newEmail: str
#     newLevel: str
#     updatedAt: dt.datetime

#     masterAdminToken: str

#     class Config:
#         orm_mode = True

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