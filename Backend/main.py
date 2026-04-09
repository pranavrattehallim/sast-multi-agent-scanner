import uuid, zipfile, shutil, json, threading
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from BASEwAGENTS import run_multi_agent_scan, DEFAULT_MODEL

BASE = Path.home() / "sast-workspace"
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def paths(job_id):
    return {
        "upload":    BASE / "uploads"   / job_id,
        "workspace": BASE / "workspace" / job_id,
        "output":    BASE / "outputs"   / job_id,
        "status":    BASE / "jobs"      / job_id / "status.json",
    }

def write_status(job_id, **kwargs):
    p = paths(job_id)["status"]
    p.parent.mkdir(parents=True, exist_ok=True)
    current = json.loads(p.read_text()) if p.exists() else {}
    current.update(kwargs)
    p.write_text(json.dumps(current))

def run_pipeline(job_id: str, model: str):
    p = paths(job_id)
    try:
        # Extract zip
        write_status(job_id, status="scanning", stage="Extracting archive", progress=20,
                     report_ready=False, error=None)
        p["workspace"].mkdir(parents=True, exist_ok=True)
        p["output"].mkdir(parents=True, exist_ok=True)

        zip_path = p["upload"] / "source.zip"
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(p["workspace"])

        # Count files for progress reporting
        from BASEwAGENTS import collect_files
        files = collect_files(str(p["workspace"]))
        total = len(files)
        write_status(job_id, stage="Running agents", progress=35,
                     total_files=total, files_scanned=0)

        # Run the full pipeline — output goes to our output dir, not inside workspace
        run_multi_agent_scan(
            folder=str(p["workspace"]),
            scanner_model=model,
            critic_model=model,
            reporter_model=model,
            output_dir=str(p["output"]),  # ← redirected here
        )

        # Confirm report exists
        pdf = p["output"] / "final_report.pdf"
        md  = p["output"] / "final_report.md"
        if not pdf.exists() and not md.exists():
            raise FileNotFoundError("Report was not generated.")

        write_status(job_id, status="completed", stage="Done", progress=100,
                     files_scanned=total, report_ready=True, error=None)

        # Clean up upload + workspace
        shutil.rmtree(p["upload"], ignore_errors=True)
        shutil.rmtree(p["workspace"], ignore_errors=True)

    except Exception as e:
        write_status(job_id, status="failed", stage="Error",
                     error=str(e), progress=0, report_ready=False)

@app.post("/api/scans")
async def create_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    model: str = Form(DEFAULT_MODEL),
):
    job_id = str(uuid.uuid4())
    p = paths(job_id)
    p["upload"].mkdir(parents=True, exist_ok=True)

    (p["upload"] / "source.zip").write_bytes(await file.read())
    write_status(job_id, status="queued", stage="Queued", progress=10,
                 report_ready=False, files_scanned=0, total_files=0, error=None)

    background_tasks.add_task(run_pipeline, job_id, model)
    return {"job_id": job_id, "status": "queued"}

@app.get("/api/scans/{job_id}/status")
def get_status(job_id: str):
    p = paths(job_id)["status"]
    if not p.exists():
        return JSONResponse({"error": "job not found"}, status_code=404)
    return {**json.loads(p.read_text()), "job_id": job_id}

@app.get("/api/scans/{job_id}/report")
def get_report(job_id: str):
    out = paths(job_id)["output"]
    # Prefer PDF, fall back to markdown
    for name, mime in [("final_report.pdf", "application/pdf"),
                       ("final_report.md",  "text/markdown")]:
        f = out / name
        if f.exists():
            return FileResponse(f, media_type=mime, filename=name)
    return JSONResponse({"error": "report not ready"}, status_code=404)