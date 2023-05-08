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
def getAdmins(db: Session = Depends(get_db)):
    try:
        dbAdmins = ta.getAdmins(db)
        return dbAdmins
    except Exception:
        return {'response': 500, 'message': traceback.format_exc()}

@app.post("/ASCEPUPR/ADMIN/CREATE_ACCOUNT/")
def createAdmin(userName:str, passwd:str, name:str, email:str, adminLevel:str,masterAdminLevel:str, db: Session = Depends(get_db)):
    try:
        admin = Administrators_Schemas.Administrator_CreateAccount_INPUTS(userName=userName, passwd=passwd,name=name,email=email,adminLevel=adminLevel, masterAdminLevel=masterAdminLevel)
        dbAdmin = ta.getAdminbyEmail(db, email=admin.email)
        if dbAdmin:
            raise HTTPException(status_code=409, detail="Email already registered")
        dbAdmin = ta.getAdminbyUserName(db, username=admin.userName)
        if dbAdmin:
            raise HTTPException(status_code=409, detail="User Name already registered")
        ta.createAdmin(db=db, admin=admin)
        return {'response':201, 'message':"User created"}
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

@app.get("/ASCEPUPR/ADMIN/CHANGE_PASSWD/")
def changeAdminPasswd(userName: str, newPasswd: str, oldPasswd: str = "", masterAdminLevel:str=None, db: Session = Depends(get_db)):
    try:
        admin = Administrators_Schemas.Administrator_ChangePasswd_INPUTS(userName=userName, passwd=oldPasswd, newPasswd=newPasswd,masterAdminLevel=masterAdminLevel)
        a = ta.changeAdminPasswd(db=db,admin=admin)
        if a == True:
            return {"status_code":200, 'body':"Password was changed"}
        return {"status_code":401, 'body': 'Password Not Changed: Invalid User Name or Password'}
    except Exception as e:
        return {'status_code': 500, 'body': repr(e)}
    
@app.get("/ASCEPUPR/ADMIN/ORDER_66/")
def deleteAdmin(level: str, state: str = "--i", userName: str = None, db:Session = Depends(get_db)):
    '''
        state = "--i" for individual entries; must supply with userName of entry to deleted.
        state = "--a" to kill table
    '''
    try:
        a = ta.deleteAdminEntry(db=db, admin = Administrators_Schemas.Administrator_Delete_Entry_INPUTS(masterAdminLevel=level, state=state, userName=userName))
        if a == True:
            return {"status_code":200, 'body':"Deletion was a success."}
        return {"status_code":401, 'body': 'Deletion was not successful. Check if User Name, admin level and state of execution were correct.'}
    except Exception as e:
        return {'status_code': 500, 'body': repr(e)}



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
