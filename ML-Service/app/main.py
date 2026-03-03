"""
ML Threat Detection Service - Entry Point
"""
from app.api.routes import router
from app.core.config import settings
from app.core.lifespan import lifespan
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)

app = FastAPI(
    title="Threat Detection ML Service",
    description="Serves threat probability predictions for API threat protection",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

app.include_router(router)
