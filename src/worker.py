import os
from celery import Celery
from .schema import RuleUpload

# We import the actual functions locally inside the task to avoid circular imports 
# or issues initializing FastAPI during Celery worker startup
def get_analysis_functions():
    from .api import _run_analyze_task, _run_recommend_task
    return _run_analyze_task, _run_recommend_task

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

celery_app = Celery("firewall_worker", broker=CELERY_BROKER_URL, backend=CELERY_RESULT_BACKEND)

@celery_app.task(name="run_analyze_task")
def analyze_task_celery(task_id: str, payload_dict: dict):
    _run_analyze_task, _ = get_analysis_functions()
    payload = RuleUpload(**payload_dict)
    _run_analyze_task(task_id, payload)

@celery_app.task(name="run_recommend_task")
def recommend_task_celery(task_id: str, payload_dict: dict, top_n: int, threshold: int):
    _, _run_recommend_task = get_analysis_functions()
    payload = RuleUpload(**payload_dict)
    _run_recommend_task(task_id, payload, top_n, threshold)
