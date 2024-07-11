from bottle import route, run  # type: ignore


@route("/hello")
def hello() -> str:
    return "Hello World"


run(host="localhost", port=8080, debug=True)
