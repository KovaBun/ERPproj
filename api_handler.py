#HTTP handler
from http.server import BaseHTTPRequestHandler
import json

class APIHandler(BaseHTTPRequestHandler):

    auth_service = None

    def do_POST(self):

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        data = json.loads(body)

        username = data.get("username")
        password = data.get("password")

        if self.path == "/signup":

            if self.auth_service.signup(username, password):
                response = "user created"
            else:
                response = "user already exists"

        elif self.path == "/login":

            if self.auth_service.login(username, password):
                response = "accepted"
            else:
                response = "rejected"

        else:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(response.encode())
