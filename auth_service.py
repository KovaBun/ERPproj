#AuthLogic
class AuthUser:
    def __init__(self,Database):
        self.db=Database
    def signup(self,username,password):
        return self.db.insertUser(username,password)
    def login(self,username,password):
        return True if self.db.getUser(username,password) is not None else False
    
