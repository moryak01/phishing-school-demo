import os
from flask import Flask, render_template, request, jsonify
from checker import analyze_url

app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/check")
def api_check():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    result = analyze_url(url)

    if "error" in result:
        return jsonify(result), 400

    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)