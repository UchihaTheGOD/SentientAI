"""Lab routes — listing, detail pages, and submission endpoint."""
from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.services.auth_service import get_current_user
from app.services.analysis import analyze_lab_submission
from app.labs import list_labs, get_lab
from app.template_env import templates

router = APIRouter(tags=["labs"])


@router.get("/labs", response_class=HTMLResponse)
def labs_page(
    request: Request,
    user: User = Depends(get_current_user),
):
    labs = list_labs()
    return templates.TemplateResponse("labs.html", {
        "request": request,
        "user": user,
        "labs": labs,
    })


@router.get("/labs/{lab_id}", response_class=HTMLResponse)
def lab_detail(
    lab_id: str,
    request: Request,
    user: User = Depends(get_current_user),
):
    lab = get_lab(lab_id)
    if not lab:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    return templates.TemplateResponse("lab_detail.html", {
        "request": request,
        "user": user,
        "lab": lab,
    })


@router.post("/api/lab/{lab_id}/submit", response_class=HTMLResponse)
def submit_lab(
    lab_id: str,
    request: Request,
    payload: str = Form(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    lab = get_lab(lab_id)
    if not lab:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    # Run the sandboxed lab handler
    handler = lab["handler"]
    lab_result = handler(payload)

    # Run full analysis pipeline
    result = analyze_lab_submission(
        db=db,
        user_id=user.id,
        lab_id=lab_id,
        lab_category=lab["category"],
        payload=payload,
        lab_result=lab_result,
    )

    # If blocked, redirect to block page
    if result["blocked"]:
        return RedirectResponse(
            url=f"/blocked?event_id={result['event_id']}&lab_id={lab_id}",
            status_code=303,
        )

    return templates.TemplateResponse("attack_result.html", {
        "request": request,
        "user": user,
        "result": result,
        "lab_output": lab_result.get("output", ""),
    })
