from fastapi import APIRouter, Depends
from jwt1 import get_current_user, fake_users_db

shop_router = APIRouter(tags=["Shop"])

@shop_router.get("/shops")
def get_available_shops(current_user = Depends(get_current_user)):
    print(current_user)
    return {f"shops for {current_user['username']}":["Araz","Bolmart","Bravo"]}


@shop_router.get("/discount")
def get_discount_for_user(current_user = Depends(get_current_user)):
    current_user = current_user["username"]
    user_data = fake_users_db[current_user]
    user_status = user_data["status"]
    if user_status=="VIP":
        discount_amount = 15
    elif user_status == "Regular":
        discount_amount = 5
    else:
        discount_amount = 0

    return {"discount_amount":discount_amount}
