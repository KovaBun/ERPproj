#AuthLogic
class AuthUser:
    def __init__(self,Database):
        self.db=Database
    def signup(self,username,password,public_key):
        return self.db.insertUser(username,password,public_key)
    def login(self,username,password,public_key):
        return True if self.db.getUser(username,password,public_key) is not None else False
    
