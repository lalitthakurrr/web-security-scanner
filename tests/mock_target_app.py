import uvicorn
from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, PlainTextResponse

app = FastAPI(title="Vulnerable Test Application Target")

@app.get("/", response_class=HTMLResponse)
def home(response: Response):
    # Intentionally omit CSP, HSTS, X-Frame-Options, X-Content-Type-Options
    response.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    response.headers["X-Powered-By"] = "PHP/7.4.3"
    
    # Insecure Cookie (Missing Secure, HttpOnly, SameSite)
    response.set_cookie(key="session_token", value="xyz123abc456", httponly=False, secure=False)

    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Test Application</title>
        <!-- TODO: Remove debug credentials before production release! Admin user: admin / Pass: SuperSecret123 -->
    </head>
    <body>
        <h1>Welcome to Vulnerable Shop Target</h1>
        <p>This application is designed specifically for testing security scanner rules.</p>
        <nav>
            <a href="/login">User Login</a> |
            <a href="/products">Product Catalog</a> |
            <a href="/contact">Contact Support</a>
        </nav>
    </body>
    </html>
    """
    return html_content

@app.get("/login", response_class=HTMLResponse)
def login():
    return """
    <html>
    <body>
        <h2>Login Form</h2>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" />
            <input type="password" name="password" placeholder="Password" />
            <button type="submit">Sign In</button>
        </form>
    </body>
    </html>
    """

@app.get("/products", response_class=HTMLResponse)
def products():
    return "<html><body><h1>Products Catalog</h1><a href='/'>Back Home</a></body></html>"

@app.get("/contact", response_class=HTMLResponse)
def contact():
    return "<html><body><h1>Contact Page</h1><a href='/'>Back Home</a></body></html>"

@app.get("/.env", response_class=PlainTextResponse)
def exposed_env():
    return "DB_HOST=127.0.0.1\nDB_USER=root\nDB_PASSWORD=SuperSecretPass123!\nAPI_SECRET_KEY=sk_live_998877665544\n"

@app.get("/.git/HEAD", response_class=PlainTextResponse)
def exposed_git():
    return "ref: refs/heads/main\n"

@app.get("/robots.txt", response_class=PlainTextResponse)
def robots():
    return "User-agent: *\nDisallow: /admin\nDisallow: /internal/\n"

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8888)
