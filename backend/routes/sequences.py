from fastapi import APIRouter

router = APIRouter(
    prefix="/sequences",
    tags=["Sequences"]
)

@router.get("/")
def get_sequences():

    return {
        "message": "Sequence correlation endpoint"
    }