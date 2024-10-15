from fastapi import FastAPI
from login1 import login_router
from shop1 import shop_router
app = FastAPI(title="My Awesome Project",version="0.1.0")

app.include_router(login_router)
app.include_router(shop_router)