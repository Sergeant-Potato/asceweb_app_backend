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
from starlette.status import HTTP_204_NO_CONTENT, HTTP_401_UNAUTHORIZED, HTTP_200_OK

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
        return {'response': HTTP_204_NO_CONTENT, 'message': traceback.format_exc()}

@app.post("/ASCEPUPR/ADMIN/CREATE_ACCOUNT/", status_code=HTTP_200_OK)
def createAdmin(userName:str, passwd:str, name:str, email:str, adminLevel:str, db: Session = Depends(get_db)):
    try:
        admin = Administrators_Schemas.Administrator_CreateAccount_INPUTS(userName=userName, passwd=passwd,name=name,email=email,adminLevel=adminLevel)
        dbAdmin = ta.getAdminbyEmail(db, email=admin.email)
        if dbAdmin:
            raise HTTPException(status_code=400, detail="Email already registered")
        dbAdmin = ta.getAdminbyUserName(db, username=admin.userName)
        if dbAdmin:
            raise HTTPException(status_code=400, detail="User Name already registered")
        ta.createAdmin(db=db, admin=admin)
        return {'response':HTTP_200_OK, 'message':"User created"}
    except Exception as e:
        return {'response': HTTP_204_NO_CONTENT, 'message': repr(e)}    # I left this since this can help us, still. It can be deleted later on.

@app.get("/ASCEPUPR/ADMIN/LOGIN/", status_code=HTTP_200_OK, response_model=Administrators_Schemas.Administrator_Validate_User)
def loginAdmin(userName:str, passwd: str, token: str = None, db: Session = Depends(get_db)):
    '''
        La variable a es la variable con el contenido retornado por la funcion loginAdmin. Recuerda que retorna una lista con 2
        elementos, donse el primero [0] es un entero y el segundo [1] es el string del token o un texto.

        El if verificara si el valor del entero en [0] es 1, 2 o 3, si si, pues retorna un status code 200 y en el cuerpo pone un string,
        sea el texto o el token. Acurdate que el HTTP_200_OK es un variable con un entero 200.
        El else, retorna que la perona no esta autorizada, pq es tu 4 caso.

        Si no corre, ya que no lo he probado desde antes de los updates, puede que sea por el response model?
    '''
    try:
        admin = Administrators_Schemas.Administrator_LoginAccount_INPUTS(userName=userName,passwd=passwd,token=token)
        a = ta.loginAdmin(db,admin = admin)
        if a[0] >=1 and a[0] <= 3:
            return {"status_code":HTTP_200_OK, 'body':a[1]}
        else:
            return {"status_code":HTTP_401_UNAUTHORIZED, 'body':a[1]}
    except Exception as e:
        return {'status_code': HTTP_204_NO_CONTENT, 'body': repr(e)}


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

@app.get("/ASCEPUPR/ADMIN/CHANGE_PASSWD/", status_code=HTTP_200_OK)
def changeAdminPasswd(userName: str, oldPasswd: str, newPasswd: str, db: Session = Depends(get_db)):
    try:
        admin = Administrators_Schemas.Administrator_ChangePasswd_INPUTS(userName=userName, passwd=oldPasswd, newPasswd=newPasswd)
        a = ta.changeAdminPasswd(db=db,admin=admin)
        if a == True:
            return {"status_code":HTTP_200_OK, 'body':"Password was changed"}
        return {"status_code":HTTP_401_UNAUTHORIZED, 'body': 'Password Not Changed: Invalid User Name or Password'}
    except Exception as e:
        return {'status_code': HTTP_204_NO_CONTENT, 'body': repr(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
