# from fastapi import FastAPI
# from Backend.CRUD_FUNCTIONS.router import user
# import os

# app = FastAPI()

# app.include_router(user)

# if _name_ == "_main_":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))

import traceback
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session
from Backend.TESTS import Test_Admins as ta
from Backend.SCHEMAS import Administrators_Schemas
from Backend.CONFIG.connection import engine, Base, SessionLocal

# chapter_members.Base.metadata.create_all(bind=connection.engine)
Base.metadata.create_all(bind = engine)

app = FastAPI()
# user= APIRouter()
#dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Changed this functino response model
@app.get("/ASCEPUPR/ADMIN/GET_ADMINS/", response_model=list[Administrators_Schemas.Administrator_GETTER])
def getAdmins(masterAdminToken: str, db: Session = Depends(get_db)):
    try:
        dbAdmins = ta.getAdmins(db,admin=Administrators_Schemas.Administrator_MasterAdminToken(masterAdminToken=masterAdminToken))
        return dbAdmins
    except Exception:
        return {'response': 500, 'message': traceback.format_exc()}

@app.post("/ASCEPUPR/ADMIN/CREATE_ACCOUNT/")
def createAdmin(userName:str, passwd:str, name:str, email:str, adminLevel:str,masterAdminToken:str, db: Session = Depends(get_db)):
    try:
        admin = Administrators_Schemas.Administrator_CreateAccount_INPUTS(userName=userName, passwd=passwd,name=name,email=email,adminLevel=adminLevel, masterAdminToken=masterAdminToken)
        dbAdmin = ta.getAdminbyEmail(db, email=admin.email)
        if dbAdmin:
            raise HTTPException(status_code=409, detail="Email already registered")
        dbAdmin = ta.getAdminbyUserName(db, username=admin.userName)
        if dbAdmin:
            raise HTTPException(status_code=409, detail="User Name already registered")
        if ta.createAdmin(db=db, admin=admin):
            return {'response':201, 'message':"User created"}
        else:
            raise Exception
    except Exception as e:
        return {'response': 500, 'message': repr(e)}    # I left this since this can help us, still. It can be deleted later on.

@app.post("/ASCEPUPR/ADMIN/CREATE_MASTER_ADMIN/")
def createAdmin(userName:str, passwd:str, name:str, email:str, db: Session = Depends(get_db)):
    '''
        Testing purposes or failsafe
    '''
    try:
        admin = Administrators_Schemas.Administrator_CreateAccount_INPUTS(userName=userName, passwd=passwd,name=name,email=email,adminLevel="MA", masterAdminToken="0")
        dbAdmin = ta.getAdminbyEmail(db, email=admin.email)
        if dbAdmin:
            raise HTTPException(status_code=409, detail="Email already registered")
        dbAdmin = ta.getAdminbyUserName(db, username=admin.userName)
        if dbAdmin:
            raise HTTPException(status_code=409, detail="User Name already registered")
        if ta.createMasterAdmin(db=db, admin=admin):
            return {'response':201, 'message':"User created"}
        else:
            raise Exception
    except Exception as e:
        return {'response': 500, 'message': repr(e)}    # I left this since this can help us, still. It can be deleted later on.

@app.get("/ASCEPUPR/ADMIN/LOGIN/", response_model=Administrators_Schemas.Administrator_Validate_User)
def loginAdmin(userName:str, passwd: str, token: str = None, db: Session = Depends(get_db)):
    try:
        admin = Administrators_Schemas.Administrator_LoginAccount_INPUTS(userName=userName,passwd=passwd,token=token)
        a = ta.loginAdmin(db,admin = admin)
        return {"status_code":a[0], 'body':a[1]}
    except Exception as e:
        return {'status_code': 500, 'body': repr(e)}


# @app.post("/Content/AdminLogin/")
# def loginAdmin(admin: Administrators_Schemas.Administrator_LoginAccount_IN, db: Session = Depends(get_db)) -> bool:
#     dbAdmin = ta.loginAdmin(db,admin=admin)
#     if dbAdmin == False:
#         raise HTTPException(status_code=401, detail="Wrong User Name or Password")
#     return dbAdmin

# # @app.post("/validation/", response_model=Administrators_Schemas.get_adta)
# @app.post("/validation/", status_code=200 )
# def validateuser(user: Administrators_Schemas.Administrator_LoginAccount_IN, db: Session = Depends(get_db)):
#     # a = ta.validateUser(db, username=admin.userName.get_secret_value(), password=admin.password.get_secret_value())
#     a = ta.validateUser(db, user=user)
#     print(a)
#     if a['msg'] == "User validated":
#         return {"status":HTTP_200_OK, 'message':a}
#     # print(a)
#     # return Response(status_code=HTTP_200_OK)
#     # return {"status":HTTP_200_OK, 'message':a}
#     # return {'userName':a[0], 'password':a[1], 'status': HTTP_200_OK}

@app.get("/ASCEPUPR/ADMIN/CHANGE_PASSWD_EMAIL/")
def changeAdminPasswd(userName: str, masterAdminToken: str, newPasswd: str = None, newEmail: str = None, db: Session = Depends(get_db)):
    try:
        admin = Administrators_Schemas.Administrator_ChangePasswdEmail_INPUTS(userName=userName,masterAdminToken=masterAdminToken, newPasswd=newPasswd,newEmail=newEmail)
        a = ta.changeAdminPasswdEmail(db=db,admin=admin)
        if a == True:
            return {"status_code":200, 'body':"Data was changed."}
        return {"status_code":401, 'body': 'Data was not changed: Invalid User Name'}
    except Exception as e:
        return {'status_code': 500, 'body': repr(e)}
    
@app.get("/ASCEPUPR/ADMIN/DEL_ACCOUNT/")
def deleteAdmin(masterAdminToken: str, email: str, db:Session = Depends(get_db)):
    try:
        a = ta.deleteAdminEntry(db=db, admin = Administrators_Schemas.Administrator_Delete_Entry_INPUTS(masterAdminToken=masterAdminToken, email=email))
        if a == True:
            return {"status_code":200, 'body':"Deletion was a success."}
        return {"status_code":401, 'body': 'Deletion was not successful. Check if token and email were correct.'}
    except Exception as e:
        return {'status_code': 500, 'body': repr(e)}

@app.get("/ASCEPUPR/ADMIN/DEL_ALL/")
def deleteAdmin(masterAdminToken: str, db:Session = Depends(get_db)):
    '''
        What I remember about the rise of the Empire is ... is how quiet it was. During the waning hours of the Clone Wars, 
        the 501st Legion was discreetly transferred back to Coruscant. It was a silent trip. We all knew what was about to 
        happen, and what we were about to do. Did we have any doubts? Any private, traitorous thoughts? Perhaps, but no one 
        said a word. Not on the flight to Coruscant, not when Order 66 came down, and not when we marched into the Jedi Temple. 
        Not a word.

        This will not delete master admins for security measure.
    '''
    try:
        a = ta.deleteAdminAll(db=db, admin = Administrators_Schemas.Administrator_MasterAdminToken(masterAdminToken=masterAdminToken))
        if a == True:
            return {"status_code":200, 'body':"Deletion was a success."}
        return {"status_code":401, 'body': 'Deletion was not successful. Check if token is correct.'}
    except Exception as e:
        return {'status_code': 500, 'body': repr(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
