#Server
from http.server import HTTPServer
from database import Database
from auth_service import AuthUser
from api_handler import APIHandler

db=Database()
auth=AuthUser(db)
APIHandler.auth_service=auth
server = HTTPServer(("localhost",8000),APIHandler)
print("Server started...")
server.serve_forever()

