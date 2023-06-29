from flask import Flask
from flask import request
from markupsafe import escape

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def process_token():
    if request.method == "GET":
        print("GET", request.json)
        return request.args
    elif request.method == "POST":
        print(request.json)
        return request.json
